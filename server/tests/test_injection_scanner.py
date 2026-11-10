"""
Pruebas unitarias para server/modules/pentesting/injection_scanner.py
(InjectionScanner)

Contexto (auditoría de Pentesting, continuación en vivo del 2026-10-18,
tras el ítem 1 ya completado para gobuster/ffuf/patator/searchsploit/
zap_scanner/sqlmap): el usuario corrió dos scans reales contra DVWA con
el proyecto ya corregido y, en ambos, el reporte mostró 3 `sqli_results`
con `simulated: true` ("SQL Injection — Error Based (DVWA)", "Command
Injection (DVWA)", "Path Traversal / LFI (DVWA)"). Se pidieron los logs
del contenedor `celery-worker` (no `api` -- la ejecución real del scan
corre en un worker de Celery separado) para ese mismo job, y confirmaron
exactamente el mismo patrón §2.1 ya corregido 8 veces en esta auditoría,
encontrado aquí por primera vez:

    DVWA auth OK — cookie obtenida (security=low forzado)
    ...
    InjectionScanner → target=http://dvwa:80 lab=dvwa
      ↳ Técnica: sql              endpoints: 2
      ↳ Técnica: xss              endpoints: 3
      ↳ Técnica: command          endpoints: 1
      ↳ Técnica: path_traversal   endpoints: 1
      ↳ Técnica: ssrf             endpoints: 1
    InjectionScanner completado: 0 hallazgos en 2.7s (lab=dvwa)
    InjectionScanner: retornando simulación para dvwa

El log confirma que el scan corrió de verdad (login real, 8 endpoints
reales probados en 5 técnicas, sin ninguna excepción de tester) y que 0
hallazgos fue un resultado honesto -- no un fallo. Pero `scan()` tenía:

    if not all_findings and lab_type != LabType.GENERIC:
        all_findings = self._simulate(target, lab_type)

que tomaba ese "no encontré nada real" contra un lab CONOCIDO (DVWA/
Juice Shop/WebGoat) y lo reemplazaba por 3 hallazgos fijos inventados por
lab. A diferencia de los demás módulos de la auditoría, este no depende
de un binario externo que pueda estar "no disponible" -- corre siempre en
Python puro -- así que no hay aquí un caso legítimo de simulación
equivalente a "herramienta ausente". Corregido: `_simulate()` ya no se
llama en ningún caso; 0 hallazgos reales es siempre el resultado final,
sea cual sea el lab.

Ejecutar:
    cd server && python3 -m unittest tests.test_injection_scanner -v
"""

import sys
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))  # server/

from modules.pentesting.injection_scanner import (  # noqa: E402
    InjectionScanner, LabType, InjectionFinding, InjectionType,
    Endpoint, XXETester, SSRFTester, CommandInjectionTester,
)


def _scanner():
    s = InjectionScanner.__new__(InjectionScanner)
    s.timeout = 600
    return s


class TestScanNeverFabricatesOnZeroRealFindings(unittest.TestCase):
    """Regresión del defecto principal: 0 hallazgos reales contra un lab
    conocido (DVWA/Juice Shop/WebGoat) debe devolver [], nunca los 3
    hallazgos fijos de _simulate()."""

    def _run_scan_with_all_testers_finding_nothing(self, target):
        scanner = _scanner()
        with patch('modules.pentesting.injection_scanner.HTTPClient'), \
             patch.object(InjectionScanner, '_detect_lab',
                          wraps=InjectionScanner._detect_lab) as _dl:
            # Todos los testers "corren" (no lanzan excepción) pero no
            # confirman ninguna inyección -- exactamente el caso real
            # observado en los logs del usuario.
            with patch('modules.pentesting.injection_scanner.SQLInjectionTester.test', return_value=[]), \
                 patch('modules.pentesting.injection_scanner.NoSQLInjectionTester.test', return_value=[]), \
                 patch('modules.pentesting.injection_scanner.XPathInjectionTester.test', return_value=[]), \
                 patch('modules.pentesting.injection_scanner.XXETester.test', return_value=[]), \
                 patch('modules.pentesting.injection_scanner.XSSTester.test', return_value=[]), \
                 patch('modules.pentesting.injection_scanner.CommandInjectionTester.test', return_value=[]), \
                 patch('modules.pentesting.injection_scanner.PathTraversalTester.test', return_value=[]), \
                 patch('modules.pentesting.injection_scanner.SSRFTester.test', return_value=[]), \
                 patch('modules.pentesting.injection_scanner.SSTITester.test', return_value=[]), \
                 patch('modules.pentesting.injection_scanner.LDAPInjectionTester.test', return_value=[]):
                return scanner.scan(target)

    def test_zero_findings_against_dvwa_returns_empty_list_not_simulated(self):
        result = self._run_scan_with_all_testers_finding_nothing('http://dvwa:80')
        self.assertEqual(
            result, [],
            "0 hallazgos reales contra DVWA (un lab conocido) debe ser [], "
            "no los 3 hallazgos fijos de _simulate() (SQL Injection, "
            "Command Injection, Path Traversal).",
        )

    def test_zero_findings_against_juice_shop_returns_empty_list(self):
        result = self._run_scan_with_all_testers_finding_nothing('http://juice-shop:3000')
        self.assertEqual(result, [])

    def test_zero_findings_against_webgoat_returns_empty_list(self):
        result = self._run_scan_with_all_testers_finding_nothing('http://webgoat:8080')
        self.assertEqual(result, [])

    def test_simulate_is_never_called_when_scan_runs_for_real(self):
        scanner = _scanner()
        with patch('modules.pentesting.injection_scanner.HTTPClient'), \
             patch.object(scanner, '_simulate') as mock_simulate, \
             patch('modules.pentesting.injection_scanner.SQLInjectionTester.test', return_value=[]), \
             patch('modules.pentesting.injection_scanner.NoSQLInjectionTester.test', return_value=[]), \
             patch('modules.pentesting.injection_scanner.XPathInjectionTester.test', return_value=[]), \
             patch('modules.pentesting.injection_scanner.XXETester.test', return_value=[]), \
             patch('modules.pentesting.injection_scanner.XSSTester.test', return_value=[]), \
             patch('modules.pentesting.injection_scanner.CommandInjectionTester.test', return_value=[]), \
             patch('modules.pentesting.injection_scanner.PathTraversalTester.test', return_value=[]), \
             patch('modules.pentesting.injection_scanner.SSRFTester.test', return_value=[]), \
             patch('modules.pentesting.injection_scanner.SSTITester.test', return_value=[]), \
             patch('modules.pentesting.injection_scanner.LDAPInjectionTester.test', return_value=[]):
            scanner.scan('http://dvwa:80')
        mock_simulate.assert_not_called()

    def test_real_finding_from_one_tester_is_still_returned(self):
        """Regresión de seguridad: un hallazgo real confirmado por un
        tester SÍ debe seguir reportándose (el fix no apaga el módulo)."""
        scanner = _scanner()
        real_finding = InjectionFinding(
            name="SQL Injection real", description="desc",
            severity="high", injection_type=InjectionType.SQL_ERROR,
            url="http://dvwa:80/vulnerabilities/sqli/", parameter="id",
            payload="' OR 1=1--", method="GET", simulated=False,
            evidence="real SQL error",
        )
        with patch('modules.pentesting.injection_scanner.HTTPClient'), \
             patch('modules.pentesting.injection_scanner.SQLInjectionTester.test', return_value=[real_finding]), \
             patch('modules.pentesting.injection_scanner.NoSQLInjectionTester.test', return_value=[]), \
             patch('modules.pentesting.injection_scanner.XPathInjectionTester.test', return_value=[]), \
             patch('modules.pentesting.injection_scanner.XXETester.test', return_value=[]), \
             patch('modules.pentesting.injection_scanner.XSSTester.test', return_value=[]), \
             patch('modules.pentesting.injection_scanner.CommandInjectionTester.test', return_value=[]), \
             patch('modules.pentesting.injection_scanner.PathTraversalTester.test', return_value=[]), \
             patch('modules.pentesting.injection_scanner.SSRFTester.test', return_value=[]), \
             patch('modules.pentesting.injection_scanner.SSTITester.test', return_value=[]), \
             patch('modules.pentesting.injection_scanner.LDAPInjectionTester.test', return_value=[]):
            result = scanner.scan('http://dvwa:80')
        # LAB_ENDPOINTS[DVWA]['sql'] tiene más de un endpoint, así que el
        # tester mockeado se invoca una vez por endpoint -- lo que importa
        # para esta regresión es que el hallazgo real sí se reporte (y
        # nunca quede ahogado o reemplazado por datos simulados).
        self.assertGreaterEqual(len(result), 1)
        self.assertTrue(all(r['name'] == "SQL Injection real" for r in result))
        self.assertFalse(any(r['simulated'] for r in result))


class TestDetectLab(unittest.TestCase):

    def test_detects_dvwa(self):
        self.assertEqual(InjectionScanner._detect_lab('http://dvwa:80'), LabType.DVWA)

    def test_detects_juice_shop(self):
        self.assertEqual(InjectionScanner._detect_lab('http://juice-shop:3000'), LabType.JUICE_SHOP)

    def test_detects_webgoat(self):
        self.assertEqual(InjectionScanner._detect_lab('http://webgoat:8080'), LabType.WEBGOAT)

    def test_unknown_target_is_generic(self):
        self.assertEqual(InjectionScanner._detect_lab('http://example.test'), LabType.GENERIC)


class TestOastBlindProbes(unittest.TestCase):
    """Fase 3 (2026-11, OAST/Interactsh, autorizada por el usuario):
    XXETester/SSRFTester/CommandInjectionTester registran una sonda ciega
    en `pending_probes` SOLO cuando (a) se les dio un `oast_canary` y
    (b) ningún payload in-band confirmó nada -- nunca reportan un
    "hallazgo" por la sonda en sí (sería fabricar evidencia que todavía
    no existe; ver interactsh_client.py y orchestrator.collect_oast_findings())."""

    def _mock_client(self, response_text="<html>sin nada reconocible</html>", status_code=200):
        client = MagicMock()
        resp = MagicMock()
        resp.text = response_text
        resp.status_code = status_code
        client.request.return_value = resp
        return client

    # ── XXETester ─────────────────────────────────────────────────────────

    def test_xxe_records_probe_when_no_in_band_finding_and_canary_given(self):
        client = self._mock_client()
        tester = XXETester(client, oast_canary="abc123.oast.pro", pending_probes=[])
        endpoint = Endpoint("/b2b/v2/", "POST", "xml", in_body=True,
                            headers={"Content-Type": "application/xml"})
        findings = tester.test(endpoint, "http://target")
        self.assertEqual(findings, [])
        self.assertEqual(len(tester.pending_probes), 1)
        probe = tester.pending_probes[0]
        self.assertEqual(probe['technique'], 'xxe')
        self.assertEqual(probe['url'], 'http://target/b2b/v2/')
        self.assertEqual(probe['parameter'], 'xml')
        self.assertEqual(probe['method'], 'POST')
        self.assertTrue(probe['label'])  # label no vacío

    def test_xxe_does_not_record_probe_without_canary(self):
        client = self._mock_client()
        tester = XXETester(client, oast_canary=None, pending_probes=[])
        endpoint = Endpoint("/b2b/v2/", "POST", "xml", in_body=True,
                            headers={"Content-Type": "application/xml"})
        tester.test(endpoint, "http://target")
        self.assertEqual(tester.pending_probes, [])

    def test_xxe_does_not_record_probe_when_in_band_finding_exists(self):
        client = self._mock_client(response_text="<?xml?><root>/etc/passwd: root:x:0:0:...</root>")
        tester = XXETester(client, oast_canary="abc123.oast.pro", pending_probes=[])
        endpoint = Endpoint("/b2b/v2/", "POST", "xml", in_body=True,
                            headers={"Content-Type": "application/xml"})
        findings = tester.test(endpoint, "http://target")
        self.assertGreaterEqual(len(findings), 1)
        # Ya hay evidencia real in-band -- no se dispara ninguna sonda ciega
        # adicional (sería redundante, y mezclar lo confirmado con lo
        # "pendiente" es exactamente el tipo de confusión que este diseño
        # evita).
        self.assertEqual(tester.pending_probes, [])

    # ── SSRFTester ────────────────────────────────────────────────────────

    def test_ssrf_records_probe_when_no_in_band_finding_and_canary_given(self):
        client = self._mock_client()
        tester = SSRFTester(client, oast_canary="abc123.oast.pro", pending_probes=[])
        endpoint = Endpoint("/rest/product/reviews", "GET", "id")
        findings = tester.test(endpoint, "http://target")
        self.assertEqual(findings, [])
        self.assertEqual(len(tester.pending_probes), 1)
        self.assertEqual(tester.pending_probes[0]['technique'], 'ssrf')

    def test_ssrf_does_not_record_probe_without_canary(self):
        client = self._mock_client()
        tester = SSRFTester(client, oast_canary=None, pending_probes=[])
        endpoint = Endpoint("/rest/product/reviews", "GET", "id")
        tester.test(endpoint, "http://target")
        self.assertEqual(tester.pending_probes, [])

    # ── CommandInjectionTester ───────────────────────────────────────────

    def test_command_records_probe_when_no_in_band_finding_and_canary_given(self):
        client = self._mock_client()
        tester = CommandInjectionTester(client, oast_canary="abc123.oast.pro", pending_probes=[])
        endpoint = Endpoint("/vulnerabilities/exec/", "POST", "ip")
        findings = tester.test(endpoint, "http://target")
        self.assertEqual(findings, [])
        self.assertEqual(len(tester.pending_probes), 1)
        self.assertEqual(tester.pending_probes[0]['technique'], 'command')

    def test_command_does_not_record_probe_without_canary(self):
        client = self._mock_client()
        tester = CommandInjectionTester(client, oast_canary=None, pending_probes=[])
        endpoint = Endpoint("/vulnerabilities/exec/", "POST", "ip")
        tester.test(endpoint, "http://target")
        self.assertEqual(tester.pending_probes, [])

    def test_command_does_not_record_probe_when_in_band_finding_exists(self):
        client = self._mock_client(response_text="uid=0(root) gid=0(root) groups=0(root)")
        tester = CommandInjectionTester(client, oast_canary="abc123.oast.pro", pending_probes=[])
        endpoint = Endpoint("/vulnerabilities/exec/", "POST", "ip")
        findings = tester.test(endpoint, "http://target")
        self.assertGreaterEqual(len(findings), 1)
        self.assertEqual(tester.pending_probes, [])

    # ── Probe labels are shared via a single list instance ──────────────

    def test_pending_probes_list_is_shared_across_calls(self):
        """`pending_probes` es la MISMA lista para todos los testers de un
        scan (así es como InjectionScanner.scan() las recolecta todas al
        final) -- dos testers que comparten la lista deben ambos agregarle
        sin pisarse."""
        shared = []
        client = self._mock_client()
        xxe = XXETester(client, oast_canary="c.oast.pro", pending_probes=shared)
        ssrf = SSRFTester(client, oast_canary="c.oast.pro", pending_probes=shared)
        xxe.test(Endpoint("/b2b/v2/", "POST", "xml", in_body=True), "http://target")
        ssrf.test(Endpoint("/rest/product/reviews", "GET", "id"), "http://target")
        self.assertEqual(len(shared), 2)
        self.assertEqual({p['technique'] for p in shared}, {'xxe', 'ssrf'})


class TestScanOastIntegration(unittest.TestCase):
    """Fase 3: InjectionScanner.scan() en sí -- compatibilidad hacia atrás
    cuando oast_canary=None, y correcta exposición de
    self._last_oast_probes cuando sí hay sondas pendientes."""

    def _patch_all_testers_except(self, exclude=()):
        """Devuelve los context managers de patch para todos los testers
        salvo los nombres en `exclude` (que el caller parchea aparte, para
        poder inspeccionar/controlar su comportamiento real)."""
        names = ['SQLInjectionTester', 'NoSQLInjectionTester', 'XPathInjectionTester',
                 'XXETester', 'XSSTester', 'CommandInjectionTester',
                 'PathTraversalTester', 'SSRFTester', 'SSTITester', 'LDAPInjectionTester']
        return [patch(f'modules.pentesting.injection_scanner.{n}.test', return_value=[])
                for n in names if n not in exclude]

    def test_scan_without_oast_canary_keeps_last_oast_probes_empty(self):
        scanner = _scanner()
        patches = self._patch_all_testers_except()
        with patch('modules.pentesting.injection_scanner.HTTPClient'):
            for p in patches:
                p.start()
            try:
                result = scanner.scan('http://dvwa:80')
            finally:
                for p in patches:
                    p.stop()
        self.assertEqual(result, [])
        self.assertEqual(scanner._last_oast_probes, [])

    def test_scan_with_oast_canary_exposes_pending_probes_on_scanner(self):
        """Verifica que scan() reparte la MISMA lista `pending_probes` a
        XXETester/SSRFTester/CommandInjectionTester y la expone después en
        self._last_oast_probes -- sin tocar el valor de retorno (que sigue
        siendo solo hallazgos confirmados in-band, nunca sondas)."""
        scanner = _scanner()

        def xxe_side_effect(self, endpoint, base_url):
            # Simula el comportamiento real: sin hallazgo in-band + canary
            # -> registra una sonda.
            self._record_oast_probe('xxe', endpoint, base_url, 'XXE_BLIND (OOB)')
            return []

        def ssrf_side_effect(self, endpoint, base_url):
            self._record_oast_probe('ssrf', endpoint, base_url, 'SSRF blind probe (OOB)')
            return []

        with patch('modules.pentesting.injection_scanner.HTTPClient'), \
             patch('modules.pentesting.injection_scanner.SQLInjectionTester.test', return_value=[]), \
             patch('modules.pentesting.injection_scanner.NoSQLInjectionTester.test', return_value=[]), \
             patch('modules.pentesting.injection_scanner.XPathInjectionTester.test', return_value=[]), \
             patch('modules.pentesting.injection_scanner.XXETester.test', xxe_side_effect), \
             patch('modules.pentesting.injection_scanner.XSSTester.test', return_value=[]), \
             patch('modules.pentesting.injection_scanner.CommandInjectionTester.test', return_value=[]), \
             patch('modules.pentesting.injection_scanner.PathTraversalTester.test', return_value=[]), \
             patch('modules.pentesting.injection_scanner.SSRFTester.test', ssrf_side_effect), \
             patch('modules.pentesting.injection_scanner.SSTITester.test', return_value=[]), \
             patch('modules.pentesting.injection_scanner.LDAPInjectionTester.test', return_value=[]):
            result = scanner.scan('http://dvwa:80', oast_canary='abc123.oast.pro')

        # El valor de retorno sigue siendo solo hallazgos confirmados --
        # ninguna sonda pendiente se cuela ahí.
        self.assertEqual(result, [])
        # Pero self._last_oast_probes sí las expone, una por endpoint
        # probado por cada tester instrumentado (DVWA tiene 1 endpoint xxe
        # -- en realidad 0, DVWA no define 'xxe' en LAB_ENDPOINTS -- y 1
        # endpoint ssrf).
        techniques_found = {p['technique'] for p in scanner._last_oast_probes}
        self.assertIn('ssrf', techniques_found)
        self.assertTrue(all('label' in p and p['label'] for p in scanner._last_oast_probes))


if __name__ == '__main__':
    unittest.main()
