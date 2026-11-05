#!/usr/bin/env python3
"""PowerBeam Day 11, phase 8: explicit SMTP dispatch, no automatic sending.

An SMTP acceptance is *not* final mailbox delivery. The queue's `delivered`
ack means "SMTP accepted", only. A crash between acceptance and ack may
cause retry/duplicate. Keep the sender manual until verified with a provider.
"""

import argparse
from email.message import EmailMessage
import fcntl
import json
import os
from pathlib import Path
import re
import smtplib
import ssl
import stat
import sys

import alert_queue
import alert_notifier

DEFAULT_SOURCE = Path('/var/lib/powerbeam-monitor/alerts.jsonl')
EMAIL_PATTERN = re.compile(r"[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+\Z")


def validate_address(address):
    """Restrict header input to single simple mailbox (no display name/list)."""
    if not isinstance(address, str) or len(address) > 254 or not EMAIL_PATTERN.fullmatch(address):
        raise ValueError('Dirección de correo inválida')
    return address


def make_email(alert, sender, recipient):
    sender = validate_address(sender)
    recipient = validate_address(recipient)
    formatted = alert_notifier.make_message(alert)
    msg = EmailMessage()
    msg['From'] = sender
    msg['To'] = recipient
    msg['Subject'] = formatted['subject']
    msg['X-PowerBeam-Alert-ID'] = formatted['alert_id']
    msg.set_content(formatted['body'], charset='utf-8')
    return msg


def read_password(path):
    """Read a private password file (NOT repo, argv, logs or environment)."""
    path = Path(path)
    flags = os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0)
    fd = os.open(path, flags)
    try:
        mode = os.fstat(fd)
        if not stat.S_ISREG(mode.st_mode):
            raise ValueError('Credencial: no es archivo regular')
        if mode.st_mode & 0o077:
            raise ValueError('Credencial: requiere permisos 0600 o más restrictivos')
        if mode.st_uid not in (os.geteuid(), 0):
            raise ValueError('Credencial: propietario inesperado')
        with os.fdopen(fd, 'rb', closefd=False) as stream:
            raw = stream.read(4097)
        if not (1 <= len(raw) <= 4096):
            raise ValueError('Credencial: tamaño inválido')
        try:
            password = raw.decode('utf-8').rstrip('\r\n')
        except UnicodeDecodeError as exc:
            raise ValueError('Credencial: codificación inválida') from exc
        if not password or '\n' in password or '\r' in password:
            raise ValueError('Credencial: formato inválido')
        return password
    finally:
        os.close(fd)


def smtp_sender(*, host, port, tls_mode, username, password, timeout=15):
    """Return a callable that sends one message per verified TLS session."""
    if not isinstance(host, str) or not host.strip() or any(x in host for x in '\r\n\t '):
        raise ValueError('Servidor SMTP inválido')
    if type(port) is not int or not (1 <= port <= 65535):
        raise ValueError('Puerto SMTP inválido')
    if tls_mode not in ('ssl', 'starttls'):
        raise ValueError('Solo se permite SMTP mediante TLS')
    if not isinstance(username, str) or not username or any(x in username for x in '\r\n'):
        raise ValueError('Usuario SMTP inválido')
    if not isinstance(password, str) or not password:
        raise ValueError('Contraseña SMTP vacía')
    context = ssl.create_default_context()

    def send(msg):
        if tls_mode == 'ssl':
            with smtplib.SMTP_SSL(host, port, timeout=timeout, context=context) as server:
                server.login(username, password)
                refused = server.send_message(msg)
        else:
            with smtplib.SMTP(host, port, timeout=timeout) as server:
                server.ehlo()
                server.starttls(context=context)
                server.ehlo()
                server.login(username, password)
                refused = server.send_message(msg)
        if refused:
            raise smtplib.SMTPRecipientsRefused(refused)
    return send


def dispatch(state_path, send, *, source=DEFAULT_SOURCE, sender, recipient, max_alerts=10):
    """Send pending alerts sequentially and ack each after SMTP acceptance.

    Independent flock serializes *dispatchers*, not producers or manual ack.
    No exact-once guarantee exists across SMTP acceptance and local ack.
    """
    if type(max_alerts) is not int or not (1 <= max_alerts <= 10):
        raise ValueError('--max-alerts debe estar entre 1 y 10')
    validate_address(sender)
    validate_address(recipient)
    state_path = Path(state_path)
    lock_path = state_path.with_name('smtp-dispatch.lock')
    flags = os.O_CREAT | os.O_RDWR | getattr(os, 'O_NOFOLLOW', 0)
    fd = os.open(lock_path, flags, 0o600)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise ValueError('Lock de envío inválido')
        fcntl.flock(fd, fcntl.LOCK_EX)
        status = alert_queue.run('status', source, state_path)
        pending = status['pending_alerts'][:max_alerts]
        accepted_ids = []
        acked_ids = []
        error = None
        needs_reconciliation = False
        for alert in pending:
            aid = alert['alert_id']
            # Re-check because an operator may have acknowledged it manually.
            current = alert_queue.run('status', source, state_path)['pending_alerts']
            if aid not in {x['alert_id'] for x in current}:
                continue
            msg = make_email(alert, sender, recipient)
            try:
                send(msg)
            except Exception as exc:
                # Deliberately don't print exception string; SMTP server
                # responses might include sensitive information.
                error = {'alert_id': aid, 'stage': 'smtp', 'error_type': type(exc).__name__}
                break
            accepted_ids.append(aid)
            try:
                alert_queue.run('ack', source, state_path, alert_id=aid, reason='delivered')
            except (OSError, ValueError, json.JSONDecodeError) as exc:
                needs_reconciliation = True
                error = {'alert_id': aid, 'stage': 'ack', 'error_type': type(exc).__name__}
                break
            acked_ids.append(aid)
        latest = alert_queue.run('status', source, state_path)
        return {
            'action': 'smtp-send', 'dry_run': False,
            'accepted_by_smtp': len(accepted_ids), 'acknowledged': len(acked_ids),
            'acknowledged_ids': acked_ids, 'pending_total': latest['pending'],
            'needs_reconciliation': needs_reconciliation, 'error': error,
            'note': 'SMTP accepted does not guarantee mailbox delivery. Crash may cause duplicate.'
        }
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


def main(argv=None):
    parser = argparse.ArgumentParser(description='PowerBeam SMTP: envío explícito, nunca automático')
    parser.add_argument('command', choices=['send'])
    parser.add_argument('--source', type=Path, default=DEFAULT_SOURCE)
    parser.add_argument('--state', required=True, type=Path)
    parser.add_argument('--sender', required=True)
    parser.add_argument('--recipient', required=True)
    parser.add_argument('--smtp-host', required=True)
    parser.add_argument('--smtp-port', required=True, type=int)
    parser.add_argument('--tls-mode', required=True, choices=['ssl', 'starttls'])
    parser.add_argument('--smtp-user', required=True)
    parser.add_argument('--password-file', required=True, type=Path)
    parser.add_argument('--max-alerts', default=1, type=int)
    parser.add_argument('--confirm-live-send', required=True, choices=['YES'])
    args = parser.parse_args(argv)
    try:
        # Fail before network usage if queue inaccessible, address or secret invalid.
        validate_address(args.sender)
        validate_address(args.recipient)
        status = alert_queue.run('status', args.source, args.state)
        if status['pending'] == 0:
            print(json.dumps({'action': 'smtp-send', 'accepted_by_smtp': 0,
                              'acknowledged': 0, 'pending_total': 0,
                              'note': 'Sin alertas pendientes; no se ha enviado nada.'}, indent=2))
            return 0
        password = read_password(args.password_file)
        send = smtp_sender(host=args.smtp_host, port=args.smtp_port,
                           tls_mode=args.tls_mode, username=args.smtp_user,
                           password=password)
        result = dispatch(args.state, send, source=args.source,
                          sender=args.sender, recipient=args.recipient,
                          max_alerts=args.max_alerts)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        # Never echo path or SMTP response if it could reveal configuration.
        print(f'ERROR: {type(exc).__name__}; operación detenida', file=sys.stderr)
        return 1
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 1 if result['error'] else 0


if __name__ == '__main__':
    sys.exit(main())
