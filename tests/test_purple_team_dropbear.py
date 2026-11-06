"""Pruebas de regresión Purple Team basadas en Dropbear."""

import sys
import unittest
from datetime import datetime
from pathlib import Path

sys.path.insert(
    0,
    str(Path(__file__).resolve().parents[1] / "scripts")
)

from auth_detector import parse_event
from security_monitor import analyze


DEVICE = "192.0.2.20"
KALI = "192.0.2.30"


def log(timestamp, message):
    return (
        f"{timestamp} source={DEVICE} "
        f"<84>Nov  6 12:45:31 dropbear[868]: "
        f"{message}\n"
    )


def failure(timestamp):
    return log(
        timestamp,
        f"Bad password attempt for 'ubnt' "
        f"from {KALI}:44660"
    )


class PurpleTeamDropbearTests(unittest.TestCase):

    def test_01_recognizes_real_dropbear_format(self):
        event = parse_event(
            failure("2026-11-06T13:45:31+01:00")
        )

        self.assertIsNotNone(event)
        self.assertEqual(
            event[2], "contrasena_incorrecta"
        )

    def test_02_identifies_kali_not_device(self):
        event = parse_event(
            failure("2026-11-06T13:45:31+01:00")
        )

        self.assertEqual(event[1], KALI)
        self.assertNotEqual(event[1], DEVICE)

    def test_03_preserves_reception_timezone(self):
        event = parse_event(
            failure("2026-11-06T13:45:31+01:00")
        )

        self.assertEqual(
            event[0],
            datetime.fromisoformat(
                "2026-11-06T13:45:31+01:00"
            )
        )

    def test_04_connection_is_not_auth_failure(self):
        line = log(
            "2026-11-06T13:13:45+01:00",
            f"Child connection from {KALI}:45976"
        )

        self.assertIsNone(parse_event(line))

    def test_05_negotiation_error_is_not_auth_failure(self):
        line = log(
            "2026-11-06T13:13:46+01:00",
            "Exit before auth: No matching algo hostkey"
        )

        self.assertIsNone(parse_event(line))

    def test_06_exit_does_not_double_count_failure(self):
        lines = [
            failure("2026-11-06T13:45:31+01:00"),
            log(
                "2026-11-06T13:45:32+01:00",
                "Exit before auth "
                "(user 'ubnt', 1 fails): Exited normally"
            )
        ]

        alerts, counts = analyze(lines)

        self.assertEqual(counts["auth_events"], 1)
        self.assertEqual(counts["bad_password"], 1)
        self.assertEqual(alerts, [])

    def test_07_two_failures_and_success_soc002(self):
        lines = [
            failure("2026-11-06T13:45:00+01:00"),
            failure("2026-11-06T13:45:30+01:00"),
            log(
                "2026-11-06T13:46:00+01:00",
                f"Password auth succeeded for 'ubnt' "
                f"from {KALI}:44660"
            )
        ]

        alerts, counts = analyze(lines)

        self.assertEqual(counts["SOC-002"], 1)
        self.assertEqual(alerts[0]["rule_id"], "SOC-002")
        self.assertEqual(alerts[0]["source_ip"], KALI)

    def test_08_five_failures_soc001(self):
        lines = [
            failure(
                f"2026-11-06T13:45:{second:02d}+01:00"
            )
            for second in (0, 10, 20, 30, 40)
        ]

        alerts, counts = analyze(lines)

        self.assertEqual(counts["SOC-001"], 1)
        self.assertEqual(alerts[0]["rule_id"], "SOC-001")
        self.assertEqual(alerts[0]["source_ip"], KALI)


if __name__ == "__main__":
    unittest.main()
