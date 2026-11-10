"""
Pruebas unitarias para server/modules/pentesting/sqlmap.py (SQLMapEnterpriseScanner)

Contexto (auditoría de Pentesting, 2026-10-16, continuación de
§2.1/§6.5/§6.6/§6.7/gobuster/ffuf/patator/searchsploit/zap):

A diferencia de los módulos anteriores, sqlmap.py NO tiene modo de
simulación (ningún `_simulate_*`, ninguna clave 'simulated' en
SQLMapFinding) -- scan() devuelve [] limpio cuando la herramienta no está
disponible o el target es inválido. El parseo real (`_parse_stdout_fallback`,
que solo reconoce el bloque "---\\nParameter: ...\\nType: ...\\nPayload:
...\\n---" que sqlmap únicamente emite tras confirmar una inyección real)
tampoco mostró riesgo de falso positivo.

Defecto confirmado (mismo patrón §2.1, mecanismo distinto): en
`_scan_cli_mode()`, `except subprocess.TimeoutExpired` devolvía un
SQLMapFinding real -- `name="SQLMap timeout"`, `severity=Severity.INFO`
-- en vez de una lista vacía o un item marcado como error. Como
SQLMapFinding.to_dict() no produce clave 'error' ni 'simulated':
  - lib/scan-extractors.ts: `isFinding(r) = !!r && !r.error` lo deja
    pasar -- el timeout se contaba como "1 hallazgo de inyección SQL" en
    el panel de herramientas (indistinguible de un hallazgo real).
  - app.py (paso Scoring): `not v.get('simulated', False)` también lo
    deja pasar (no tiene esa clave) -- entra a calculate_security_score()
    como vulnerabilidad real de severidad 'info'.
Corregido para devolver [] en timeout, igual que gobuster/ffuf/
searchsploit/zap.

Nota (verificado, no corregido -- confirmado como código inalcanzable sin
impacto funcional): `_parse_api_data()` tiene un bloque idéntico de
procesamiento de `injection_data` duplicado DESPUÉS de un `return
findings` (líneas ~678-689), por lo tanto nunca se ejecuta. Mismo patrón
de observación que el dead code ya señalado en reporter.py/patator.py.

Ejecutar:
    cd server && python3 -m unittest tests.test_sqlmap_scanner -v
"""

import subprocess
import sys
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))  # server/

from modules.pentesting.sqlmap import SQLMapEnterpriseScanner  # noqa: E402


def _scanner(available=True, use_api=False):
    s = SQLMapEnterpriseScanner.__new__(SQLMapEnterpriseScanner)
    s.timeout = 60
    s.level = 3
    s.risk = 2
    s.threads = 5
    s._available = available
    s.use_api = use_api
    s._api_client = None
    s._auth_config = {}
    s._headers = {}
    from modules.pentesting.sqlmap import PostExploitLevel
    s._post_exploit_level = PostExploitLevel.BASIC_ENUM
    return s


class TestScanNeverFabricatesOnFailure(unittest.TestCase):

    def test_invalid_target_returns_empty_list(self):
        s = _scanner(available=True)
        self.assertEqual(s.scan(''), [])

    def test_malformed_url_returns_empty_list(self):
        s = _scanner(available=True)
        with patch('modules.pentesting.sqlmap.urlparse') as mock_parse:
            mock_parse.return_value = MagicMock(hostname=None)
            self.assertEqual(s.scan('http://x'), [])

    def test_binary_not_available_returns_empty_list_no_simulation(self):
        """sqlmap.py no tiene modo simulado -- herramienta ausente = []."""
        s = _scanner(available=False)
        self.assertEqual(s.scan('http://example.test'), [])


class TestScanCliModeTimeoutNeverFabricatesFinding(unittest.TestCase):
    """Regresión del defecto principal: un timeout real de sqlmap debe
    devolver [], nunca un SQLMapFinding con forma de hallazgo real."""

    def setUp(self):
        self.scanner = _scanner(available=True, use_api=False)

    def test_timeout_returns_empty_list_not_info_finding(self):
        with patch('modules.pentesting.sqlmap.tempfile.mkdtemp', return_value='/tmp/fake_sqlmap_dir'), \
             patch('modules.pentesting.sqlmap.shutil.rmtree'), \
             patch.object(self.scanner, '_build_cli_command', return_value=['sqlmap', '-u', 'http://x']), \
             patch('modules.pentesting.sqlmap.subprocess.run',
                   side_effect=subprocess.TimeoutExpired(cmd='sqlmap', timeout=60)):
            result = self.scanner._scan_cli_mode('http://example.test')
        self.assertEqual(
            result, [],
            "Un timeout real de sqlmap no debe producir un SQLMapFinding "
            "'SQLMap timeout' con severidad info -- isFinding() del "
            "frontend no lo filtraría, contándolo como un hallazgo real.",
        )

    def test_generic_exception_returns_empty_list(self):
        with patch('modules.pentesting.sqlmap.tempfile.mkdtemp', return_value='/tmp/fake_sqlmap_dir'), \
             patch('modules.pentesting.sqlmap.shutil.rmtree'), \
             patch.object(self.scanner, '_build_cli_command', return_value=['sqlmap', '-u', 'http://x']), \
             patch('modules.pentesting.sqlmap.subprocess.run', side_effect=RuntimeError('boom')):
            result = self.scanner._scan_cli_mode('http://example.test')
        self.assertEqual(result, [])


class TestParseStdoutFallbackOnlyTrustsConfirmedInjectionBlocks(unittest.TestCase):
    """Verifica que el parser real solo reconoce el bloque de sqlmap que
    confirma una inyección (---/Parameter/Type/Title/Payload/---), no
    cualquier mención de la palabra 'injection' en el output."""

    def setUp(self):
        self.scanner = _scanner(available=True)

    def test_parses_confirmed_injection_block(self):
        output = (
            "sqlmap resumed the following injection point(s)\n"
            "---\n"
            "Parameter: id (GET)\n"
            "    Type: boolean-based blind\n"
            "    Title: AND boolean-based blind - WHERE or HAVING clause\n"
            "    Payload: id=1 AND 1=1\n"
            "---\n"
        )
        findings = self.scanner._parse_stdout_fallback(output, 'http://example.test')
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].parameter, 'id')
        self.assertEqual(findings[0].severity.value if hasattr(findings[0].severity, 'value') else findings[0].severity, 'critical')

    def test_plain_output_without_injection_block_returns_empty(self):
        output = "[INFO] testing connection to the target URL\n[INFO] target URL content is stable"
        findings = self.scanner._parse_stdout_fallback(output, 'http://example.test')
        self.assertEqual(findings, [])

    def test_not_injectable_message_produces_explicit_info_finding(self):
        output = "[CRITICAL] all tested parameters do not appear to be injectable, i.e. does not seem to be injectable."
        findings = self.scanner._parse_stdout_fallback(output, 'http://example.test')
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].name, "Sin SQL Injection detectada")

    def test_deduplicates_same_parameter_and_type(self):
        output = (
            "---\n"
            "Parameter: id (GET)\n"
            "    Type: boolean-based blind\n"
            "    Title: AND boolean-based blind\n"
            "    Payload: id=1 AND 1=1\n"
            "    Type: boolean-based blind\n"
            "    Title: AND boolean-based blind (duplicate)\n"
            "    Payload: id=1 AND 1=1-- dup\n"
            "---\n"
        )
        findings = self.scanner._parse_stdout_fallback(output, 'http://example.test')
        self.assertEqual(len(findings), 1)


if __name__ == '__main__':
    unittest.main()
