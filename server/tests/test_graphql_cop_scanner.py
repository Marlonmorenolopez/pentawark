"""
Pruebas unitarias para la integración de graphql-cop en Pentesting:
  - server/modules/pentesting/graphql_cop_scanner.py (GraphQLCopScanner)
  - server/modules/pentesting/orchestrator.py::run_graphql_cop()
  - server/skill_execution_registry.py (entrada 'graphql-cop')

Contexto (Fase 2 del plan de la "Auditoría de cobertura de vulnerabilidades
— PentaWark", 2026-11, autorizada explícitamente por el usuario): ver el
docstring de graphql_cop_scanner.py -- a diferencia de jwt_tool, graphql-cop
sí se invoca por subprocess real (tiene un modo `-o json` documentado),
así que estas pruebas mockean subprocess.Popen, igual que el resto de
wrappers de binarios externos del proyecto (ver test_nmap_scanner.py,
test_ffuf_scanner.py).

Ejecutar:
    cd server && python3 -m unittest tests.test_graphql_cop_scanner -v
"""

import json
import subprocess
import sys
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))  # server/

from modules.pentesting.graphql_cop_scanner import GraphQLCopScanner  # noqa: E402


def _scanner(available=True):
    s = GraphQLCopScanner.__new__(GraphQLCopScanner)
    s.timeout = 60
    s.command = ['graphql-cop'] if available else None
    s._available = available
    return s


class TestToolUnavailableReportsInfoMarkedSimulated(unittest.TestCase):

    def test_binary_missing_returns_single_info_finding_marked_simulated(self):
        scanner = _scanner(available=False)
        result = scanner.scan('http://dvwa/graphql')
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]['severity'], 'info')
        self.assertTrue(result[0]['simulated'])
        self.assertEqual(result[0]['tool'], 'graphql-cop')


class TestRealScanParsing(unittest.TestCase):

    def _mock_popen(self, stdout='', returncode=0):
        proc = MagicMock()
        proc.communicate.return_value = (stdout, '')
        proc.returncode = returncode
        return proc

    def test_vulnerable_tests_are_reported_as_findings_not_simulated(self):
        scanner = _scanner(available=True)
        payload = json.dumps([
            {'test_name': 'introspection', 'result': True, 'description': 'Introspection query is enabled'},
            {'test_name': 'csrf', 'result': True, 'description': 'CSRF protection missing'},
        ])
        with patch('modules.pentesting.graphql_cop_scanner.subprocess.Popen',
                   return_value=self._mock_popen(stdout=payload)):
            result = scanner.scan('http://juice-shop/graphql')
        self.assertEqual(len(result), 2)
        self.assertTrue(all(f['simulated'] is False for f in result))
        csrf = next(f for f in result if f['test_id'] == 'csrf')
        self.assertEqual(csrf['severity'], 'high')

    def test_non_vulnerable_tests_are_not_reported_as_findings(self):
        """Regresión del patrón §2.1: graphql-cop corrió de verdad y una
        prueba específica no encontró nada -- no debe fabricarse un
        hallazgo 'info: todo bien' ni contarse como vulnerabilidad."""
        scanner = _scanner(available=True)
        payload = json.dumps([
            {'test_name': 'introspection', 'result': False, 'description': 'Introspection disabled'},
        ])
        with patch('modules.pentesting.graphql_cop_scanner.subprocess.Popen',
                   return_value=self._mock_popen(stdout=payload)):
            result = scanner.scan('http://dvwa/graphql')
        self.assertEqual(result, [])

    def test_real_scan_with_zero_findings_returns_empty_list(self):
        scanner = _scanner(available=True)
        with patch('modules.pentesting.graphql_cop_scanner.subprocess.Popen',
                   return_value=self._mock_popen(stdout='[]')):
            result = scanner.scan('http://webgoat/graphql')
        self.assertEqual(result, [])

    def test_malformed_json_output_returns_empty_list_not_fabricated(self):
        scanner = _scanner(available=True)
        with patch('modules.pentesting.graphql_cop_scanner.subprocess.Popen',
                   return_value=self._mock_popen(stdout='not valid json at all')):
            result = scanner.scan('http://dvwa/graphql')
        self.assertEqual(result, [])

    def test_dict_wrapped_results_key_is_also_accepted(self):
        scanner = _scanner(available=True)
        payload = json.dumps({'results': [
            {'test_name': 'debug_mode', 'result': True, 'description': 'Debug mode is enabled'},
        ]})
        with patch('modules.pentesting.graphql_cop_scanner.subprocess.Popen',
                   return_value=self._mock_popen(stdout=payload)):
            result = scanner.scan('http://juice-shop/graphql')
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]['severity'], 'high')

    def test_timeout_returns_empty_list_not_fabricated(self):
        scanner = _scanner(available=True)
        proc = MagicMock()
        proc.communicate.side_effect = [
            subprocess.TimeoutExpired(cmd='graphql-cop', timeout=60),
            ('', ''),
        ]
        with patch('modules.pentesting.graphql_cop_scanner.subprocess.Popen', return_value=proc):
            result = scanner.scan('http://dvwa/graphql')
        self.assertEqual(result, [])


class TestOrchestratorRunGraphqlCop(unittest.TestCase):

    def test_run_graphql_cop_delegates_to_scanner_and_returns_its_result(self):
        import modules.pentesting.orchestrator as orch_mod

        orchestrator = orch_mod.SecurityOrchestrator.__new__(orch_mod.SecurityOrchestrator)
        orchestrator.TIMEOUTS = orch_mod.SecurityOrchestrator.TIMEOUTS
        orchestrator.graphql_cop = MagicMock()
        orchestrator.graphql_cop.scan.return_value = [
            {'name': 'Introspection enabled', 'severity': 'medium', 'tool': 'graphql-cop', 'simulated': False},
        ]
        result = orchestrator.run_graphql_cop('http://dvwa/graphql')
        orchestrator.graphql_cop.scan.assert_called_once_with('http://dvwa/graphql')
        self.assertEqual(result[0]['severity'], 'medium')

    def test_run_graphql_cop_timeout_returns_empty_list_not_sentinel(self):
        import modules.pentesting.orchestrator as orch_mod

        orchestrator = orch_mod.SecurityOrchestrator.__new__(orch_mod.SecurityOrchestrator)
        orchestrator.TIMEOUTS = orch_mod.SecurityOrchestrator.TIMEOUTS
        orchestrator.graphql_cop = MagicMock()

        def _hangs(target):
            raise orch_mod.ScanTimeoutError()

        orchestrator.graphql_cop.scan.side_effect = _hangs
        with patch.object(orch_mod, 'run_with_timeout', side_effect=lambda func, args=(), kwargs=None, seconds=0, default=None: default):
            result = orchestrator.run_graphql_cop('http://dvwa/graphql')
        self.assertEqual(result, [])


class TestSkillRegistryEntry(unittest.TestCase):

    def test_graphql_cop_registered_with_target_url_subject(self):
        import skill_execution_registry as reg

        entry = reg.get_runner_entry('graphql-cop')
        self.assertIsNotNone(entry)
        self.assertEqual(entry.runner_attr, 'run_graphql_cop')
        self.assertEqual(entry.status, 'available')
        self.assertEqual(entry.schema.subject_kind, 'target_url')
        self.assertEqual(entry.schema.fields, [])


if __name__ == '__main__':
    unittest.main()
