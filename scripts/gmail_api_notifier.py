#!/usr/bin/env python3
"""PowerBeam: manual Gmail API send-only notifier using previously authorized OAuth.

Never runs automatically; operates only on the explicitly provided alert queue.
An API success acknowledges *Google accepting* the message, not mailbox delivery.
Neither Gmail API nor the local queue can guarantee exactly-once delivery.
"""

import argparse
import base64
import fcntl
import json
import os
from pathlib import Path
import stat
import sys

import alert_queue
import gmail_oauth_authorize
import smtp_notifier

DEFAULT_TOKEN = Path.home() / '.local/share/powerbeam-security-lab/gmail-token.json'
MAX_TOKEN_BYTES = 128 * 1024


def token_data(path):
    """Read an OAuth token from a private, regular, locally owned file."""
    path = Path(path)
    if path.parent.is_symlink():
        raise ValueError('Directorio de token no puede ser un enlace')
    fd = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0))
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_uid != os.geteuid():
            raise ValueError('Token: propietario o tipo de archivo no permitido')
        if stat.S_IMODE(st.st_mode) & 0o077:
            raise ValueError('Token: permisos demasiado amplios; requiere 0600')
        if not (1 <= st.st_size <= MAX_TOKEN_BYTES):
            raise ValueError('Token: tamaño inválido')
        with os.fdopen(fd, 'rb', closefd=False) as handle:
            raw = handle.read(MAX_TOKEN_BYTES + 1)
        try:
            value = json.loads(raw)
        except (ValueError, UnicodeDecodeError) as exc:
            raise ValueError('Token: JSON inválido') from exc
        if not isinstance(value, dict) or not value.get('token'):
            raise ValueError('Token: formato incompleto')
        if gmail_oauth_authorize.SCOPE not in value.get('scopes', []):
            raise ValueError('Token: falta permiso gmail.send')
        return value
    finally:
        os.close(fd)


def load_credentials(path):
    """Load send-only credentials; refresh and persist token if needed."""
    data = token_data(path)
    try:
        from google.auth.transport.requests import Request
        from google.oauth2.credentials import Credentials
    except ImportError as exc:
        raise RuntimeError('Faltan bibliotecas Google: usa el entorno virtual OAuth') from exc
    credentials = Credentials.from_authorized_user_info(data, scopes=[gmail_oauth_authorize.SCOPE])
    if not credentials.valid:
        if not credentials.refresh_token:
            raise RuntimeError('Token expirado y sin refresh_token; vuelve a autorizar')
        credentials.refresh(Request())
        if not credentials.valid:
            raise RuntimeError('La renovación OAuth no produjo credenciales válidas')
        gmail_oauth_authorize.save_private_token(path, credentials.to_json())
    return credentials


def send_email_with_service(service, message):
    """Send a single EmailMessage; require Gmail's ID in its response."""
    payload = base64.urlsafe_b64encode(message.as_bytes()).decode('ascii')
    result = service.users().messages().send(userId='me', body={'raw': payload}).execute()
    if not isinstance(result, dict) or not isinstance(result.get('id'), str) or not result['id']:
        raise ValueError('Gmail API no devolvió ID del mensaje; aceptación incierta')
    return result['id']


def gmail_sender(token_path):
    """Create a sender; authorization occurs only after explicit send confirmation."""
    creds = load_credentials(token_path)
    try:
        from googleapiclient.discovery import build
    except ImportError as exc:
        raise RuntimeError('Faltan bibliotecas de Gmail API: usa entorno virtual OAuth') from exc
    service = build('gmail', 'v1', credentials=creds, cache_discovery=False)
    return lambda msg: send_email_with_service(service, msg)


def dispatch(state_path, send, *, source, sender, recipient, max_alerts=1):
    """Dispatch and ack sequentially, preserving pending on failures.

    A network timeout or crash after API acceptance but before ack may still
    produce a duplicate if retried. This is not exactly-once messaging.
    """
    if type(max_alerts) is not int or not (1 <= max_alerts <= 10):
        raise ValueError('--max-alerts debe estar entre 1 y 10')
    smtp_notifier.validate_address(sender)
    smtp_notifier.validate_address(recipient)
    state_path = Path(state_path)
    lock_path = state_path.with_name('gmail-api-dispatch.lock')
    fd = os.open(lock_path, os.O_CREAT | os.O_RDWR | getattr(os, 'O_NOFOLLOW', 0), 0o600)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise ValueError('Bloqueo de envío inválido')
        fcntl.flock(fd, fcntl.LOCK_EX)
        pending = alert_queue.run('status', source, state_path)['pending_alerts'][:max_alerts]
        api_accepted = []
        acknowledged = []
        error = None
        needs_reconciliation = False
        for alert in pending:
            aid = alert['alert_id']
            latest = alert_queue.run('status', source, state_path)['pending_alerts']
            if aid not in {x['alert_id'] for x in latest}:
                continue
            message = smtp_notifier.make_email(alert, sender, recipient)
            try:
                gmail_id = send(message)
                if not isinstance(gmail_id, str) or not gmail_id:
                    raise ValueError('API no confirmó ID; entrega incierta')
            except Exception as exc:
                error = {'alert_id': aid, 'stage': 'gmail_api', 'error_type': type(exc).__name__}
                # Network timeouts can happen after Gmail accepted a message.
                needs_reconciliation = True
                break
            api_accepted.append(aid)
            try:
                alert_queue.run('ack', source, state_path, alert_id=aid, reason='delivered')
            except (OSError, ValueError, json.JSONDecodeError) as exc:
                needs_reconciliation = True
                error = {'alert_id': aid, 'stage': 'ack', 'error_type': type(exc).__name__}
                break
            acknowledged.append(aid)
        latest = alert_queue.run('status', source, state_path)
        return {
            'action': 'gmail-api-send', 'dry_run': False,
            'accepted_by_gmail_api': len(api_accepted),
            'acknowledged': len(acknowledged), 'acknowledged_ids': acknowledged,
            'pending_total': latest['pending'],
            'needs_reconciliation': needs_reconciliation, 'error': error,
            'note': 'Gmail API aceptó el mensaje, no garantiza llegada al buzón ni ausencia de duplicados.'
        }
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


def main(argv=None):
    parser = argparse.ArgumentParser(description='Gmail API OAuth: envío manual explícito de alertas SOC')
    parser.add_argument('command', choices=['send'])
    parser.add_argument('--state', required=True, type=Path)
    parser.add_argument('--source', required=True, type=Path)
    parser.add_argument('--sender', required=True)
    parser.add_argument('--recipient', required=True)
    parser.add_argument('--token', type=Path, default=DEFAULT_TOKEN)
    parser.add_argument('--max-alerts', type=int, default=1)
    parser.add_argument('--confirm-live-send', choices=['YES'], required=True)
    args = parser.parse_args(argv)
    try:
        smtp_notifier.validate_address(args.sender)
        smtp_notifier.validate_address(args.recipient)
        if type(args.max_alerts) is not int or not (1 <= args.max_alerts <= 10):
            raise ValueError('max-alerts inválido')
        status = alert_queue.run('status', args.source, args.state)
        if status['pending'] == 0:
            print(json.dumps({'action': 'gmail-api-send', 'accepted_by_gmail_api': 0,
                              'acknowledged': 0, 'pending_total': 0,
                              'note': 'Sin alertas pendientes; no se ha enviado nada.'}, indent=2))
            return 0
        send = gmail_sender(args.token)
        result = dispatch(args.state, send, source=args.source, sender=args.sender,
                          recipient=args.recipient, max_alerts=args.max_alerts)
    except Exception as exc:
        # No exception string: SDK exceptions might include token, paths, payload.
        print(f'ERROR: {type(exc).__name__}; envío detenido (sin revelar credenciales)', file=sys.stderr)
        return 1
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 1 if result['error'] else 0


if __name__ == '__main__':
    sys.exit(main())
