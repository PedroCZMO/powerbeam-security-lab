"""Pruebas offline de SOC-002. Ejecutar: python3 -m unittest discover -s tests -v"""

import contextlib
import io
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

# Cargar el detector desde scripts/, sin dependencias de terceros.
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import auth_detector  # noqa: E402


def event(time, action, client="192.0.2.10", device="192.0.2.20"):
    """Registro representativo, con direcciones IP reservadas para documentación."""
    return (
        f"2026-10-30T{time}+01:00 source={device} "
        f"<14>Oct 30 11:22:17 httpd[1234]: {action} from {client}\n"
    )


BAD = "Bad password attempt for 'testuser'"
UNKNOWN = "Login attempt for nonexistent user"
OK = "Password auth succeeded for 'testuser'"


def run_detector(lines):
    output = io.StringIO()
    with patch.object(sys, "stdin", io.StringIO("".join(lines))):
        with contextlib.redirect_stdout(output):
            auth_detector.main()
    return output.getvalue()


class DetectorTests(unittest.TestCase):
    def test_alerta_dos_fallos_y_exito_en_cinco_minutos(self):
        result = run_detector([
            event("12:22:17", UNKNOWN),
            event("12:22:35", BAD),
            event("12:22:45", OK),
        ])
        self.assertIn("[SOC-002]", result)
        self.assertIn("fallos_previos=2", result)
        self.assertIn("Alertas SOC-002: 1", result)

    def test_un_fallo_no_dispara_alerta(self):
        result = run_detector([event("12:22:35", BAD), event("12:22:45", OK)])
        self.assertIn("Alertas SOC-002: 0", result)

    def test_ip_distinta_no_se_correlaciona(self):
        result = run_detector([
            event("12:22:17", UNKNOWN, client="192.0.2.10"),
            event("12:22:35", BAD, client="192.0.2.10"),
            event("12:22:45", OK, client="192.0.2.11"),
        ])
        self.assertIn("Alertas SOC-002: 0", result)

    def test_fuera_de_ventana_no_dispara(self):
        result = run_detector([
            event("12:10:00", UNKNOWN),
            event("12:11:00", BAD),
            event("12:22:45", OK),
        ])
        self.assertIn("Alertas SOC-002: 0", result)

    def test_entradas_desordenadas_se_ordenan(self):
        result = run_detector([
            event("12:22:45", OK),
            event("12:22:17", UNKNOWN),
            event("12:22:35", BAD),
        ])
        self.assertIn("Alertas SOC-002: 1", result)

    def test_filas_ajenas_ignoradas(self):
        result = run_detector([
            event("12:22:17", "System started"),
            "no es un registro syslog\n",
        ])
        self.assertIn("Correctas: 0", result)
        self.assertIn("Alertas SOC-002: 0", result)


if __name__ == "__main__":
    unittest.main()
