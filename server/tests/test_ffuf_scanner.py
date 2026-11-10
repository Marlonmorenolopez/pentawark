"""
Pruebas unitarias para:
  - server/modules/pentesting/ffuf.py                 (FfufScanner)
  - server/modules/pentesting/orchestrator.py::run_ffuf()

Contexto (auditoría de Pentesting, 2026-10-16, continuación de
§2.1/§6.5/§6.6/§6.7/gobuster):

Defecto 1 (el más significativo de este módulo): `FfufScanner.scan()`
declaraba los parámetros `custom_headers`/`cookie` en su firma, pero nunca
los usaba para construir el comando `ffuf` -- faltaba por completo el flag
`-H`. Como `SecurityOrchestrator.run_ffuf()` sí pasa el cookie de sesión
(para fuzzear como usuario autenticado, igual que hace con Gobuster y ZAP),
el resultado real era que ffuf SIEMPRE corría sin sesión: cualquier ruta
que solo existiera detrás de login nunca podía descubrirse, sin que el
scan reportara ningún error -- simplemente no aparecía, indistinguible de
"no existe". Mismo defecto, mismo fix que ya se había aplicado a Gobuster
(comentario "FIX" ya presente en orchestrator.py::run_gobuster(), Fase 2
Bloque 3). Se corrigió agregando los `-H` correspondientes.

Defecto 2 (menor, mismo patrón que Gobuster en orchestrator.py): el
`except ScanTimeoutError`/`except Exception` de `run_ffuf()` devolvía
`[{'error': ..., 'tool': 'ffuf'}]` -- un item sin 'endpoints'. No fabrica
un endpoint falso (ffuf.py en sí nunca fabrica endpoints, ya tenía el
comentario "0 resultados reales — no simular"), pero
`lib/scan-extractors.ts` cuenta `s.ffuf_endpoints?.length` sin filtrar
items con 'error' (a diferencia de sqli_results/patator, que sí usan
`isFinding()`) -- un timeout se contaba como "1 resultado" en el panel de
herramientas. Corregido para devolver `[]`, igual que Gobuster.

Defecto 3 (UI, verificado por lectura ya que no hay entorno para compilar
el frontend): el badge del tab "ffuf" en components/results-dashboard.tsx
y el contador de `lib/scan-extractors.ts` mostraban
`ffuf_endpoints.length` -- el número de GRUPOS (scan() envuelve su
resultado en una lista de un solo item), no la cantidad real de endpoints
descubiertos anidados en `group.endpoints`. Corregido para sumar los
endpoints anidados.

Ejecutar:
    cd server && python3 -m unittest tests.test_ffuf_scanner -v
"""

import json
import subprocess
import sys
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock, mock_open

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))  # server/

from modules.pentesting.ffuf import FfufScanner              # noqa: E402
from modules.pentesting.orchestrator import (                 # noqa: E402
    SecurityOrchestrator, ScanTimeoutError,
)


def _scanner(available=True):
    s = FfufScanner.__new__(FfufScanner)
    s.timeout = 120
    s.threads = 40
    s.rate = 100
    s.command = 'ffuf'
    s._available = available
    return s


class TestFfufAuthHeadersActuallyReachTheCommand(unittest.TestCase):
    """Regresión del defecto principal: custom_headers/cookie deben
    traducirse en flags -H reales del comando ffuf."""

    def setUp(self):
        self.scanner = _scanner(available=True)

    def _run_scan_and_capture_cmd(self, **scan_kwargs):
        captured = {}

        def fake_run(cmd, **kwargs):
            captured['cmd'] = cmd
            return MagicMock(returncode=0, stdout='', stderr='')

        with patch('modules.pentesting.ffuf.subprocess.run', side_effect=fake_run), \
             patch('modules.pentesting.ffuf.os.path.exists', return_value=False), \
             patch.object(self.scanner, '_find_system_wordlist', return_value='/app/wordlist-common.txt'), \
             patch.object(self.scanner, '_write_wordlist', return_value='/tmp/fake_wordlist.txt'):
            self.scanner.scan('http://dvwa:80', **scan_kwargs)
        return captured.get('cmd', [])

    def test_cookie_param_adds_header_flag(self):
        cmd = self._run_scan_and_capture_cmd(cookie='PHPSESSID=abc123; security=low')
        self.assertIn('-H', cmd)
        idx = cmd.index('-H')
        self.assertEqual(cmd[idx + 1], 'Cookie: PHPSESSID=abc123; security=low')

    def test_custom_headers_param_adds_header_flags(self):
        cmd = self._run_scan_and_capture_cmd(
            custom_headers={'Cookie': 'session=xyz', 'X-Custom': 'value'})
        self.assertIn('Cookie: session=xyz', cmd)
        self.assertIn('X-Custom: value', cmd)

    def test_no_auth_params_means_no_dash_h_flag(self):
        cmd = self._run_scan_and_capture_cmd()
        self.assertNotIn('-H', cmd)

    def test_custom_headers_takes_precedence_over_bare_cookie_key_collision(self):
        # Si ambos definen 'Cookie', custom_headers no debe duplicarse.
        cmd = self._run_scan_and_capture_cmd(
            custom_headers={'Cookie': 'session=from_headers'}, cookie='should_not_be_used')
        cookie_flags = [cmd[i + 1] for i, v in enumerate(cmd) if v == '-H' and cmd[i + 1].startswith('Cookie:')]
        self.assertEqual(cookie_flags, ['Cookie: session=from_headers'])


class TestFfufNeverFabricatesEndpoints(unittest.TestCase):
    """scan() en cada camino sin datos reales devuelve [] o un item
    explícitamente marcado -- nunca endpoints inventados con forma real."""

    def test_invalid_target_returns_empty_list(self):
        s = _scanner(available=True)
        self.assertEqual(s.scan(''), [])

    def test_binary_not_available_returns_clearly_simulated_data(self):
        s = _scanner(available=False)
        result = s.scan('http://example.test')
        self.assertTrue(len(result) >= 1)
        self.assertTrue(all(r.get('simulated') is True for r in result))

    def test_zero_real_results_not_treated_as_simulated(self):
        s = _scanner(available=True)
        with patch('modules.pentesting.ffuf.subprocess.run',
                   return_value=MagicMock(returncode=0, stdout='', stderr='')), \
             patch('modules.pentesting.ffuf.os.path.exists', return_value=False), \
             patch.object(s, '_find_system_wordlist', return_value='/app/wordlist-common.txt'):
            result = s.scan('http://example.test')
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]['endpoints'], [])
        self.assertFalse(result[0]['simulated'])

    def test_real_endpoints_parsed_from_json_output(self):
        s = _scanner(available=True)
        fake_json = json.dumps({'results': [
            {'input': {'FUZZ': 'admin'}, 'url': 'http://example.test/admin', 'status': 200, 'length': 512, 'words': 10},
            {'input': {'FUZZ': 'secret'}, 'url': 'http://example.test/secret', 'status': 404, 'length': 0, 'words': 0},
        ]})
        with patch('modules.pentesting.ffuf.subprocess.run',
                   return_value=MagicMock(returncode=0, stdout='', stderr='')), \
             patch('modules.pentesting.ffuf.os.path.exists', return_value=True), \
             patch('builtins.open', mock_open(read_data=fake_json)), \
             patch.object(s, '_find_system_wordlist', return_value='/app/wordlist-common.txt'):
            result = s.scan('http://example.test')
        self.assertEqual(len(result[0]['endpoints']), 1, "El 404 debe excluirse (-fc 404)")
        self.assertEqual(result[0]['endpoints'][0]['status'], 200)
        self.assertFalse(result[0]['simulated'])

    def test_timeout_returns_explicit_empty_endpoints_not_fabricated(self):
        s = _scanner(available=True)
        with patch('modules.pentesting.ffuf.subprocess.run',
                   side_effect=subprocess.TimeoutExpired(cmd='ffuf', timeout=120)), \
             patch.object(s, '_find_system_wordlist', return_value='/app/wordlist-common.txt'):
            result = s.scan('http://example.test')
        self.assertEqual(result[0]['endpoints'], [])
        self.assertFalse(result[0]['simulated'])


class TestOrchestratorRunFfufNeverFabricatesOnFailure(unittest.TestCase):
    """Regresión: run_ffuf() en timeout/error debe devolver [], nunca un
    item sin 'endpoints' que lib/scan-extractors.ts cuenta como resultado."""

    def setUp(self):
        self.orchestrator = SecurityOrchestrator()

    def test_timeout_returns_empty_list(self):
        with patch.object(self.orchestrator.ffuf, 'scan',
                           side_effect=ScanTimeoutError('ffuf timeout')):
            result = self.orchestrator.run_ffuf('http://example.test')
        self.assertEqual(result, [])

    def test_generic_exception_returns_empty_list(self):
        with patch.object(self.orchestrator.ffuf, 'scan',
                           side_effect=RuntimeError('boom')):
            result = self.orchestrator.run_ffuf('http://example.test')
        self.assertEqual(result, [])

    def test_successful_scan_passes_cookie_as_custom_headers(self):
        with patch.object(self.orchestrator.ffuf, 'scan', return_value=[]) as mock_scan:
            self.orchestrator.run_ffuf('http://example.test', cookie='PHPSESSID=abc')
        _, kwargs = mock_scan.call_args
        self.assertEqual(kwargs.get('custom_headers'), {'Cookie': 'PHPSESSID=abc'})


if __name__ == '__main__':
    unittest.main()
