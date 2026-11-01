"""Pruebas offline SOC-001. Comando: python3 -m unittest discover -s tests -v"""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from bruteforce_detector import detect  # noqa: E402


def event(time, kind="Bad password attempt for 'testuser'", ip="192.0.2.10"):
    return (
        f"2026-10-30T{time}+01:00 source=192.0.2.20 "
        f"<14>Oct 30 11:22:17 httpd[1234]: {kind} from {ip}\n"
    )


BAD = "Bad password attempt for 'testuser'"
UNKNOWN = "Login attempt for nonexistent user"
SUCCESS = "Password auth succeeded for 'testuser'"


class SOC001Tests(unittest.TestCase):
    def test_cinco_fallos_misma_ip_en_cinco_minutos_alerta(self):
        logs = [event(f"12:0{i}:00") for i in range(5)]
        alerts, _ = detect(logs)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0][2], 5)

    def test_cuatro_fallos_no_alerta(self):
        alerts, _ = detect(event(f"12:0{i}:00") for i in range(4))
        self.assertEqual(alerts, [])

    def test_ips_distintas_no_se_suman(self):
        logs = [event("12:00:00", ip="192.0.2.10")] * 3 + [
            event("12:00:30", ip="192.0.2.11")
        ] * 2
        alerts, _ = detect(logs)
        self.assertEqual(alerts, [])

    def test_fuera_de_ventana_no_alerta(self):
        logs = [event(f"12:0{i}:00") for i in range(4)] + [event("12:10:00")]
        alerts, _ = detect(logs)
        self.assertEqual(alerts, [])

    def test_mezcla_usuario_inexistente_y_password(self):
        logs = [event("12:00:00", UNKNOWN)] * 2 + [event("12:01:00", BAD)] * 3
        alerts, counts = detect(logs)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(counts["usuario_inexistente"], 2)
        self.assertEqual(counts["contrasena_incorrecta"], 3)

    def test_exitos_no_se_contabilizan_como_fallos(self):
        logs = [event("12:00:00", BAD)] * 4 + [event("12:00:30", SUCCESS)]
        alerts, counts = detect(logs)
        self.assertEqual(alerts, [])
        self.assertEqual(counts["autenticacion_correcta"], 1)

    def test_sin_duplicados_dentro_de_cinco_minutos(self):
        logs = [event("12:00:00")] * 7
        alerts, _ = detect(logs)
        self.assertEqual(len(alerts), 1)

    def test_eventos_desordenados_ordenados_por_fecha(self):
        logs = [event(f"12:0{i}:00") for i in [4, 2, 0, 3, 1]]
        alerts, _ = detect(logs)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0][0].minute, 4)

    def test_se_ignoran_lineas_no_relacionadas(self):
        alerts, counts = detect(["malformed line\n", event("12:00:00", "System started")])
        self.assertEqual(alerts, [])
        self.assertEqual(dict(counts), {})

    def test_una_ip_segunda_alerta_despues_cooldown(self):
        logs = [event("12:00:00")] * 5 + [event("12:06:00")] * 5
        alerts, _ = detect(logs)
        self.assertEqual(len(alerts), 2)


if __name__ == "__main__":
    unittest.main()
