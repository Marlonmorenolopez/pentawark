"""
Pruebas unitarias para:
  - server/modules/pentesting/gobuster.py        (GobusterEnterpriseScanner)
  - server/modules/pentesting/orchestrator.py::run_gobuster()

Contexto (auditoría de Pentesting, 2026-10-16, continuación de §6.5/§6.6/§6.7):
GobusterEnterpriseScanner.scan() en sí NO tiene un patrón de falso positivo
fabricado como el de §2.1 (Nmap/Wappalyzer/Nuclei) -- target inválido,
binario ausente, wordlist no resuelta y "sin salida" devuelven correctamente
`[]`. El defecto real estaba un nivel más arriba, en
SecurityOrchestrator.run_gobuster() (orchestrator.py): sus manejadores de
ScanTimeoutError y Exception devolvían un item con FORMA de directorio real
(`{'path': '/timeout', 'status': 0, ...}` / `{'error': str(e), 'skipped':
True}`), que:
  1. server/app.py usa para armar `extra_urls` hacia ZAP sin chequear
     'skipped' -- "/timeout" se inyectaba como ruta real descubierta.
  2. server/utils/reporter.py renderiza "Directorios Encontrados (N)" sin
     filtrar 'skipped' -- el reporte exportado mostraría un directorio
     fabricado, sin badge "Simulado" (no lleva 'simulated').
El frontend (results-dashboard.tsx) sí filtraba 'skipped' correctamente --
el defecto no llegaba a la UI, pero sí al reporte exportado y a la
inyección en ZAP.

Corrección: igual que nmap/wappalyzer/nuclei, un timeout o error sin datos
reales devuelve lista vacía, nunca un item con forma de hallazgo.

Ejecutar:
    cd server && python3 -m unittest tests.test_gobuster_scanner -v
"""

import sys
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))  # server/

from modules.pentesting.gobuster import GobusterEnterpriseScanner  # noqa: E402
from modules.pentesting.orchestrator import (                      # noqa: E402
    SecurityOrchestrator, ScanTimeoutError,
)


def _scanner(available=True):
    s = GobusterEnterpriseScanner.__new__(GobusterEnterpriseScanner)
    s.threads = 20
    s.timeout = 400
    s.skip_ssl_verify = False
    s.follow_redirects = False
    s.auto_tech_detect = True
    from modules.pentesting.gobuster import AdaptiveRateLimiter, TechFingerprint
    s._rate_limiter = AdaptiveRateLimiter(0)
    s._headers = {}
    s._command = 'gobuster'
    s._available = available
    s._exclude_lengths = set()
    s._exclude_length_ranges = []
    s._tech_fingerprint = TechFingerprint.GENERIC
    s._baseline_size = None
    s._server_header = None
    return s


class TestGobusterScanNeverFabricatesDirectories(unittest.TestCase):
    """GobusterEnterpriseScanner.scan() -- cada camino sin datos reales
    devuelve [], nunca un placeholder con forma de directorio."""

    def setUp(self):
        self.scanner = _scanner(available=True)

    def test_invalid_target_returns_empty_list(self):
        result = self.scanner.scan('')
        self.assertEqual(result, [])

    def test_binary_not_available_returns_empty_list(self):
        s = _scanner(available=False)
        result = s.scan('http://example.test')
        self.assertEqual(result, [])

    @patch('modules.pentesting.gobuster.os.path.exists', return_value=False)
    def test_no_wordlist_resolved_returns_empty_list(self, mock_exists):
        with patch.object(self.scanner, '_probe_target', return_value={}):
            result = self.scanner.scan('http://example.test', wordlist='/nonexistent.txt')
        self.assertEqual(result, [])

    @patch('modules.pentesting.gobuster.os.path.exists', return_value=True)
    def test_execution_failure_with_no_output_returns_empty_list(self, mock_exists):
        with patch.object(self.scanner, '_probe_target', return_value={}), \
             patch.object(self.scanner, '_execute_with_retry', return_value=(False, '', 'boom')):
            result = self.scanner.scan('http://example.test', wordlist='/app/wordlist-common.txt')
        self.assertEqual(result, [])


class TestGobusterParseOutput(unittest.TestCase):
    """_parse_output() con salidas reales de gobuster (formato -q estándar
    y el formato con corchetes), incluida la clasificación de falsos
    positivos por tamaño y por rutas reservadas de Windows."""

    def setUp(self):
        self.scanner = _scanner(available=True)

    def test_parses_standard_format_with_redirect(self):
        output = "/admin                (Status: 301) [Size: 178] [--> /admin/]\n"
        results = self.scanner._parse_output(output)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].path, '/admin')
        self.assertEqual(results[0].status, 301)
        self.assertEqual(results[0].redirect_url, '/admin/')
        self.assertEqual(results[0].type, 'redirect')

    def test_parses_bracket_format(self):
        output = "/login [Status: 200, Size: 2048]\n"
        results = self.scanner._parse_output(output)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].path, '/login')
        self.assertEqual(results[0].status, 200)

    def test_excluded_size_marked_as_false_positive(self):
        self.scanner.set_exclude_lengths(178)
        output = "/fake (Status: 200) [Size: 178]\n"
        results = self.scanner._parse_output(output)
        self.assertTrue(results[0].is_false_positive)

    def test_windows_reserved_device_name_marked_as_false_positive(self):
        output = "/con (Status: 200) [Size: 512]\n"
        results = self.scanner._parse_output(output)
        self.assertTrue(results[0].is_false_positive)

    def test_duplicate_paths_deduplicated(self):
        output = "/admin (Status: 200) [Size: 100]\n/admin (Status: 200) [Size: 100]\n"
        results = self.scanner._parse_output(output)
        self.assertEqual(len(results), 1)

    def test_empty_output_returns_empty_list(self):
        self.assertEqual(self.scanner._parse_output(''), [])

    def test_garbage_line_is_skipped_not_fabricated(self):
        output = "===============================\nGobuster v3.6\nnot a real result line\n"
        self.assertEqual(self.scanner._parse_output(output), [])


class TestGobusterTimeoutReadsPartialResults(unittest.TestCase):
    """En timeout, _execute_with_retry intenta leer resultados parciales del
    archivo de salida -- nunca fabrica un resultado si el archivo real no
    tiene nada."""

    def setUp(self):
        self.scanner = _scanner(available=True)

    def test_timeout_with_no_output_file_returns_failure_not_fabricated_data(self):
        with patch('modules.pentesting.gobuster.subprocess.run',
                   side_effect=__import__('subprocess').TimeoutExpired(cmd='gobuster', timeout=1)):
            self.scanner._output_file = '/tmp/__does_not_exist_gobuster_test__.txt'
            success, out, err = self.scanner._execute_with_retry(['gobuster'], timeout=1)
        self.assertFalse(success)
        self.assertEqual(out, '')


class TestOrchestratorRunGobusterNeverFabricatesOnFailure(unittest.TestCase):
    """
    Regresión del defecto confirmado en este punto de la auditoría:
    SecurityOrchestrator.run_gobuster() debe devolver [] en timeout/error,
    nunca un item con forma de directorio real (ver docstring del módulo).
    """

    def setUp(self):
        self.orchestrator = SecurityOrchestrator()

    def test_timeout_returns_empty_list_not_fake_timeout_path(self):
        with patch.object(self.orchestrator.gobuster, 'scan',
                           side_effect=ScanTimeoutError('gobuster timeout')):
            result = self.orchestrator.run_gobuster('http://example.test')
        self.assertEqual(
            result, [],
            "En timeout, run_gobuster() NUNCA debe devolver un item con "
            "forma de directorio (ej. {'path': '/timeout', ...}) -- eso se "
            "inyectaba como URL real a ZAP y se mostraba en el reporte "
            "exportado como si fuera un hallazgo real.",
        )

    def test_generic_exception_returns_empty_list_not_fake_error_item(self):
        with patch.object(self.orchestrator.gobuster, 'scan',
                           side_effect=RuntimeError('conexión rechazada')):
            result = self.orchestrator.run_gobuster('http://example.test')
        self.assertEqual(result, [])

    def test_successful_scan_still_filters_false_positives_and_skipped(self):
        fake_results = [
            {'path': '/admin', 'status': 200, 'is_false_positive': False},
            {'path': '/fake', 'status': 200, 'is_false_positive': True},
            {'path': '/timeout', 'status': 0, 'skipped': True},
        ]
        with patch.object(self.orchestrator.gobuster, 'scan', return_value=fake_results):
            result = self.orchestrator.run_gobuster('http://example.test')
        self.assertEqual(result, [{'path': '/admin', 'status': 200, 'is_false_positive': False}])

    def test_dry_run_returns_clearly_simulated_mock_data(self):
        result = self.orchestrator.run_gobuster('http://example.test', dry_run=True)
        self.assertTrue(len(result) > 0)
        self.assertTrue(all(d.get('simulated') is True for d in result))


if __name__ == '__main__':
    unittest.main()
