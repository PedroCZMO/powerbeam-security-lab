#!/usr/bin/env python3
"""PowerBeam Security Lab: offline health of Gmail OAuth token (no network/writes).

Reads only *non-secret properties* of a private Google authorized-user JSON.
Does not determine whether the refresh token is accepted by Google, nor its
server-side expiration, and does not send mail or refresh any credentials.
"""

import argparse
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import stat
import sys

SCOPE = 'https://www.googleapis.com/auth/gmail.send'
DEFAULT_TOKEN = Path.home() / '.local/share/powerbeam-security-lab/gmail-token.json'
MAX_BYTES = 128 * 1024


class InspectionError(Exception):
    """Error code safe to show in logs (never includes secret contents)."""


def _private_json(path, expected_uid=None):
    """Read through directory FD, refuse symlinks and overly broad permissions."""
    path = Path(path)
    uid = os.geteuid() if expected_uid is None else expected_uid
    dfd = None
    fd = None
    try:
        dfd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        directory = os.fstat(dfd)
        if directory.st_uid != uid or stat.S_IMODE(directory.st_mode) & 0o077:
            raise InspectionError('INSECURE_DIRECTORY')
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=dfd)
        file_stat = os.fstat(fd)
        if not stat.S_ISREG(file_stat.st_mode) or file_stat.st_uid != uid:
            raise InspectionError('INVALID_FILE')
        if file_stat.st_nlink != 1 or stat.S_IMODE(file_stat.st_mode) & 0o077:
            raise InspectionError('INSECURE_FILE')
        if not (1 <= file_stat.st_size <= MAX_BYTES):
            raise InspectionError('INVALID_SIZE')
        raw = os.read(fd, MAX_BYTES + 1)
        if len(raw) > MAX_BYTES:
            raise InspectionError('INVALID_SIZE')
        try:
            data = json.loads(raw.decode('utf-8'))
        except (UnicodeError, ValueError) as exc:
            raise InspectionError('INVALID_JSON') from exc
        if not isinstance(data, dict):
            raise InspectionError('INVALID_JSON')
        return data
    except FileNotFoundError as exc:
        raise InspectionError('NOT_FOUND') from exc
    except PermissionError as exc:
        raise InspectionError('ACCESS_DENIED') from exc
    except (OSError, ValueError) as exc:
        raise InspectionError('UNREADABLE_OR_SYMLINK') from exc
    finally:
        if fd is not None:
            os.close(fd)
        if dfd is not None:
            os.close(dfd)


def _expiry_state(value, now):
    """Google token JSON typically stores `expiry` as UTC without an offset."""
    if value is None:
        return 'UNKNOWN'
    if not isinstance(value, str):
        raise InspectionError('INVALID_EXPIRY')
    try:
        expiry = datetime.fromisoformat(value.replace('Z', '+00:00'))
    except ValueError as exc:
        raise InspectionError('INVALID_EXPIRY') from exc
    if expiry.tzinfo is None:
        expiry = expiry.replace(tzinfo=timezone.utc)
    seconds_left = (expiry.astimezone(timezone.utc) - now).total_seconds()
    if seconds_left <= 0:
        return 'EXPIRED'
    return 'EXPIRING_SOON' if seconds_left <= 300 else 'VALID'


def inspect(path=DEFAULT_TOKEN, *, now=None, expected_uid=None):
    """Return intentionally redacted report about *local* OAuth readiness."""
    now = now or datetime.now(timezone.utc)
    if now.tzinfo is None or now.utcoffset() is None:
        raise ValueError('now must be timezone-aware')
    now = now.astimezone(timezone.utc)
    base = {
        'component': 'gmail_oauth',
        'inspection': 'OFFLINE_READ_ONLY',
        'remote_authorization': 'NOT_CHECKED',
        'refresh_token_expiry': 'UNKNOWN',
        'emails_sent': 0,
        'token_modified': False,
    }
    try:
        data = _private_json(path, expected_uid=expected_uid)
        if not isinstance(data.get('scopes'), list) or SCOPE not in data['scopes']:
            raise InspectionError('MISSING_GMAIL_SEND_SCOPE')
        if not isinstance(data.get('token'), str) or not data['token']:
            raise InspectionError('MISSING_ACCESS_TOKEN')
        access = _expiry_state(data.get('expiry'), now)
        refresh = isinstance(data.get('refresh_token'), str) and bool(data['refresh_token'])
        can_refresh = refresh and all(
            isinstance(data.get(k), str) and bool(data[k])
            for k in ('client_id', 'client_secret', 'token_uri')
        )
        if can_refresh:
            local_status = 'READY_LOCAL'
            detail = 'Configuracion local preparada; validez del refresh token sin verificar'
        elif access in ('VALID', 'EXPIRING_SOON'):
            local_status = 'WARNING'
            detail = 'Access token presente, pero no hay datos completos para renovarlo'
        else:
            local_status = 'CRITICAL'
            detail = 'Access token no utilizable y renovacion no preparada'
        if access == 'UNKNOWN' and local_status == 'READY_LOCAL':
            local_status = 'WARNING'
            detail = 'Caducidad del access token desconocida; refresh sin verificar'
        return {
            **base,
            'local_status': local_status,
            'access_token_state': access,
            'refresh_token_present': refresh,
            'refresh_configuration_complete': can_refresh,
            'gmail_send_scope': True,
            'private_file_and_directory': True,
            'detail': detail,
        }
    except InspectionError as exc:
        return {
            **base,
            'local_status': 'CRITICAL',
            'error_code': str(exc),
            'detail': 'No se puede validar de forma segura el token local',
        }


def main(argv=None):
    parser = argparse.ArgumentParser(description='PowerBeam: comprobacion OAuth local, sin red ni envios')
    parser.add_argument('--token', type=Path, default=DEFAULT_TOKEN)
    args = parser.parse_args(argv)
    report = inspect(args.token)
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return {'READY_LOCAL': 0, 'WARNING': 1, 'CRITICAL': 2}[report['local_status']]


if __name__ == '__main__':
    sys.exit(main())
