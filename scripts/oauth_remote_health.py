#!/usr/bin/env python3
"""PowerBeam Security Lab: explicit Gmail OAuth refresh probe (no mail, no writes).

Sends one OAuth token-renewal request to Google's official token endpoint.
Never calls Gmail API, persists credentials, or prints exception text.
The refresh-token's future validity cannot be inferred from one successful probe.
"""

import argparse
import json
from pathlib import Path
import sys

import oauth_health

TRUSTED_TOKEN_URI = 'https://oauth2.googleapis.com/token'
TIMEOUT_SECONDS = 10


class ProbeFailure(Exception):
    """Safe, static health error code; MUST NOT contain remote response text."""

    VALID_CODES = {
        'REFRESH_FAILED', 'TRANSPORT_ERROR', 'GOOGLE_LIBRARIES_MISSING',
        'INVALID_REFRESH_RESULT', 'UNEXPECTED_REFRESH_FAILURE',
    }

    def __init__(self, code):
        if code not in self.VALID_CODES:
            raise ValueError('Invalid probe error code')
        self.code = code
        super().__init__(code)


def _refresh_with_google(data):
    """Use the refresh grant only, with a bounded transport request."""
    try:
        from google.auth.exceptions import RefreshError, TransportError
        from google.auth.transport.requests import Request
        from google.oauth2.credentials import Credentials
    except ImportError:
        raise ProbeFailure('GOOGLE_LIBRARIES_MISSING') from None

    try:
        credentials = Credentials.from_authorized_user_info(
            data, scopes=[oauth_health.SCOPE]
        )
        # Do not trust a token_uri supplied by a local file for an outbound
        # request that carries a refresh token.
        if credentials.token_uri != TRUSTED_TOKEN_URI:
            raise ProbeFailure('INVALID_REFRESH_RESULT')
        transport = Request()

        def bounded_request(*args, **kwargs):
            requested = kwargs.get('timeout')
            # One bounded timeout per HTTP request, not a complete process SLA.
            if isinstance(requested, (int, float)) and not isinstance(requested, bool):
                kwargs['timeout'] = max(0.1, min(requested, TIMEOUT_SECONDS))
            else:
                kwargs['timeout'] = TIMEOUT_SECONDS
            return transport(*args, **kwargs)

        credentials.refresh(bounded_request)
        return bool(credentials.valid and credentials.token)
    except ProbeFailure:
        raise
    except RefreshError:
        raise ProbeFailure('REFRESH_FAILED') from None
    except TransportError:
        raise ProbeFailure('TRANSPORT_ERROR') from None
    except Exception:
        raise ProbeFailure('UNEXPECTED_REFRESH_FAILURE') from None


def check(token_path=oauth_health.DEFAULT_TOKEN, *, refresher=None):
    """Return a safe, secret-free report; no emails and no file modifications.

    `refresher` exists only for offline tests and accepts a token dict.
    """
    report = oauth_health.inspect(token_path)
    result = {
        'component': 'gmail_oauth',
        'inspection': 'ONLINE_REFRESH_READ_ONLY',
        'local_status': report['local_status'],
        'access_token_state': report.get('access_token_state', 'UNKNOWN'),
        'remote_authorization': 'NOT_CHECKED',
        'refresh_token_expiry': 'UNKNOWN',
        'emails_sent': 0,
        'token_modified': False,
    }
    if report['local_status'] != 'READY_LOCAL':
        result['health_status'] = 'CRITICAL' if report['local_status'] == 'CRITICAL' else 'DEGRADED'
        result['error_code'] = report.get('error_code', 'LOCAL_NOT_READY')
        return result

    try:
        data = oauth_health._private_json(token_path)
    except oauth_health.InspectionError as exc:
        result.update(health_status='CRITICAL', error_code=str(exc))
        return result

    if data.get('token_uri') != TRUSTED_TOKEN_URI:
        result.update(health_status='CRITICAL', error_code='UNTRUSTED_TOKEN_ENDPOINT')
        return result

    try:
        accepted = (refresher or _refresh_with_google)(data)
        if accepted is not True:
            raise ProbeFailure('INVALID_REFRESH_RESULT')
    except ProbeFailure as exc:
        status = 'DEGRADED' if exc.code in ('TRANSPORT_ERROR', 'GOOGLE_LIBRARIES_MISSING') else 'CRITICAL'
        result.update(health_status=status, remote_authorization='FAILED', error_code=exc.code)
    except Exception:
        # Includes exceptions from test hooks or unexpected SDK errors.
        result.update(health_status='CRITICAL', remote_authorization='FAILED',
                      error_code='UNEXPECTED_REFRESH_FAILURE')
    else:
        result.update(health_status='HEALTHY', remote_authorization='ACCEPTED')
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(
        description='PowerBeam: prueba en línea de renovación OAuth (sin Gmail ni escrituras)'
    )
    parser.add_argument('--token', type=Path, default=oauth_health.DEFAULT_TOKEN)
    parser.add_argument('--online', choices=['YES'], required=True,
                        help='Confirmación de la petición de renovación a Google')
    args = parser.parse_args(argv)
    result = check(args.token)
    print(json.dumps(result, indent=2, ensure_ascii=False))
    return {'HEALTHY': 0, 'DEGRADED': 1, 'CRITICAL': 2}[result['health_status']]


if __name__ == '__main__':
    sys.exit(main())
