#!/usr/bin/env python3
"""Authorize Gmail send-only OAuth for PowerBeam Security Lab (no email is sent)."""
import argparse
import json
import os
import stat
import tempfile
from pathlib import Path

SCOPE = 'https://www.googleapis.com/auth/gmail.send'
DEFAULT_CLIENT = Path.home() / '.config/powerbeam-security-lab/gmail-oauth-client.json'
DEFAULT_TOKEN = Path.home() / '.local/share/powerbeam-security-lab/gmail-token.json'


def validate_client_file(path):
    path = Path(path)
    if path.is_symlink() or not path.is_file():
        raise ValueError('El JSON debe ser un archivo normal, no un enlace simbolico.')
    if stat.S_IMODE(path.stat().st_mode) & 0o077:
        raise ValueError('El JSON debe tener permisos privados (chmod 600).')
    try:
        obj = json.loads(path.read_text(encoding='utf-8'))
    except (OSError, ValueError) as exc:
        raise ValueError('No se pudo leer un JSON de credenciales valido.') from exc
    if not isinstance(obj, dict) or 'installed' not in obj:
        raise ValueError('El JSON no es de tipo Aplicacion de escritorio (installed).')
    config = obj['installed']
    if not isinstance(config, dict) or not all(config.get(k) for k in ('client_id', 'client_secret', 'auth_uri', 'token_uri')):
        raise ValueError('Faltan campos de un cliente OAuth de escritorio.')
    return True


def private_directory(directory):
    directory = Path(directory)
    if directory.is_symlink():
        raise ValueError('El directorio privado no puede ser enlace simbolico.')
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    if directory.is_symlink() or not directory.is_dir():
        raise ValueError('Directorio privado invalido.')
    directory.chmod(0o700)


def save_private_token(token_path, data):
    token_path = Path(token_path)
    private_directory(token_path.parent)
    if token_path.is_symlink():
        raise ValueError('El token no puede ser enlace simbolico.')
    temp_path = None
    try:
        with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8', dir=token_path.parent, prefix='.gmail-token-', delete=False) as stream:
            temp_path = Path(stream.name)
            os.chmod(temp_path, 0o600)
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp_path, token_path)
        os.chmod(token_path, 0o600)
    finally:
        if temp_path is not None and temp_path.exists():
            temp_path.unlink()


def authorize(client_path, token_path):
    validate_client_file(client_path)
    try:
        from google.auth.transport.requests import Request
        from google.oauth2.credentials import Credentials
        from google_auth_oauthlib.flow import InstalledAppFlow
    except ImportError as exc:
        raise RuntimeError('Faltan dependencias Google: instala las librerias en el entorno virtual.') from exc

    token_path = Path(token_path)
    private_directory(token_path.parent)
    creds = None
    if token_path.exists() or token_path.is_symlink():
        if token_path.is_symlink() or not token_path.is_file() or stat.S_IMODE(token_path.stat().st_mode) & 0o077:
            raise ValueError('El token existente no es un archivo privado normal (600).')
        creds = Credentials.from_authorized_user_file(str(token_path), [SCOPE])
        if SCOPE not in (creds.scopes or []):
            raise ValueError('El token existente no tiene el permiso gmail.send.')

    if creds and creds.valid:
        print('Autorizacion OAuth vigente. No se ha enviado ningun correo.')
        return
    if creds and creds.expired and creds.refresh_token:
        creds.refresh(Request())
    else:
        flow = InstalledAppFlow.from_client_secrets_file(str(client_path), [SCOPE])
        creds = flow.run_local_server(host='127.0.0.1', port=0, open_browser=True)
    if not creds.valid:
        raise RuntimeError('Google no ha confirmado credenciales validas.')
    save_private_token(token_path, creds.to_json())
    print('OAuth autorizado y token guardado en archivo privado. No se ha enviado ningun correo.')


def main():
    parser = argparse.ArgumentParser(description='PowerBeam: autorizar OAuth para Gmail send, sin enviar correo.')
    parser.add_argument('--client', type=Path, default=DEFAULT_CLIENT)
    parser.add_argument('--token', type=Path, default=DEFAULT_TOKEN)
    parser.add_argument('--check-client', action='store_true', help='Validar JSON sin conectarse ni autorizar.')
    args = parser.parse_args()
    try:
        validate_client_file(args.client)
        if args.check_client:
            print('Cliente OAuth de escritorio: OK (sin mostrar credenciales).')
        else:
            authorize(args.client, args.token)
    except (OSError, ValueError, RuntimeError) as exc:
        print(f'ERROR: {exc}')
        raise SystemExit(1) from None


if __name__ == '__main__':
    main()
