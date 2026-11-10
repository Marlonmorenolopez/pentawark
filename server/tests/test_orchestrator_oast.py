"""
Pruebas unitarias para SecurityOrchestrator.start_oast_session() /
collect_oast_findings() / run_injection_scan() (Fase 3, 2026-11, OAST,
autorizada por el usuario) -- server/modules/pentesting/orchestrator.py.

Usa SecurityOrchestrator.__new__() (sin __init__) para evitar instanciar
los 12+ scanners reales (red, binarios externos) -- solo se configuran a
mano los atributos que cada método bajo prueba necesita, siguiendo el
mismo patrón que ya usan otros tests de este proyecto para InjectionScanner
(ver tests/test_injection_scanner.py::_scanner()).

Ejecutar:
    cd server && python3 -m unittest tests.test_orchestrator_oast -v
"""

import sys
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))  # server/

from modules.pentesting.orchestrator import (  # noqa: E402
    SecurityOrchestrator, ScanTimeoutError,
)
from modules.pentesting.interactsh_client import InteractshSession  # noqa: E402


def _orchestrator(**attrs):
    o = SecurityOrchestrator.__new__(SecurityOrchestrator)
    o.interactsh_server = 'oast.pro'
    o.injection_scanner = None
    for k, v in attrs.items():
        setattr(o, k, v)
    return o


class TestStartOastSession(unittest.TestCase):

    def test_returns_session_on_successful_registration(self):
        o = _orchestrator()

        def fake_register(self):
            # register() real también fija correlation_id/registered --
            # replicamos eso para que canary_domain funcione, igual que
            # haría una llamada real exitosa.
            self.correlation_id = 'abc123'
            self.registered = True
            return self.canary_domain
        with patch.object(InteractshSession, 'register', fake_register):
            session = o.start_oast_session()
        self.assertIsInstance(session, InteractshSession)
        self.assertEqual(session.canary_domain, 'abc123.oast.pro')
        self.assertTrue(session.registered)

    def test_returns_none_when_registration_fails(self):
        """register() devolviendo None (sin red, servidor caído) no debe
        tumbar el scan -- start_oast_session() propaga ese None tal cual,
        nunca fabrica una sesión/dominio canario falso."""
        o = _orchestrator()
        with patch.object(InteractshSession, 'register', return_value=None):
            session = o.start_oast_session()
        self.assertIsNone(session)

    def test_uses_configured_interactsh_server(self):
        o = _orchestrator(interactsh_server='my-private-interactsh.example.com')
        captured = {}

        def fake_register(self):
            captured['server'] = self.server
            return None
        with patch.object(InteractshSession, 'register', fake_register):
            o.start_oast_session()
        self.assertEqual(captured['server'], 'my-private-interactsh.example.com')


class TestCollectOastFindings(unittest.TestCase):

    def test_returns_empty_when_session_is_none(self):
        o = _orchestrator()
        self.assertEqual(o.collect_oast_findings(None), [])

    def test_returns_empty_and_deregisters_when_no_pending_probes(self):
        mock_scanner = MagicMock()
        mock_scanner._last_oast_probes = []
        o = _orchestrator(injection_scanner=mock_scanner)
        mock_session = MagicMock()
        result = o.collect_oast_findings(mock_session)
        self.assertEqual(result, [])
        mock_session.deregister.assert_called_once()
        mock_session.poll.assert_not_called()  # sin sondas, ni se consulta /poll

    def test_returns_empty_when_probes_exist_but_no_interactions(self):
        """Sonda enviada, pero Interactsh no reporta ninguna interacción
        real -- NO es evidencia de que el target sea seguro (§2.1), así
        que no se fabrica ningún hallazgo 'probablemente no vulnerable'."""
        mock_scanner = MagicMock()
        mock_scanner._last_oast_probes = [
            {'label': 'abc123', 'technique': 'ssrf', 'url': 'http://t/x',
             'parameter': 'id', 'method': 'GET'},
        ]
        o = _orchestrator(injection_scanner=mock_scanner)
        mock_session = MagicMock()
        mock_session.poll.return_value = []
        result = o.collect_oast_findings(mock_session)
        self.assertEqual(result, [])
        mock_session.deregister.assert_called_once()

    def test_probe_with_matching_interaction_becomes_confirmed_finding(self):
        mock_scanner = MagicMock()
        mock_scanner._last_oast_probes = [
            {'label': 'abc123def456', 'technique': 'xxe',
             'url': 'http://target/b2b/v2/', 'parameter': 'xml', 'method': 'POST'},
        ]
        o = _orchestrator(injection_scanner=mock_scanner)
        mock_session = MagicMock()
        mock_session.poll.return_value = [{
            'protocol': 'dns',
            'full-id': 'abc123def456.correlationid.oast.pro',
            'remote-address': '203.0.113.9',
            'timestamp': '2026-11-08T10:00:00Z',
        }]
        result = o.collect_oast_findings(mock_session)
        self.assertEqual(len(result), 1)
        finding = result[0]
        self.assertEqual(finding['tool'], 'interactsh')
        self.assertEqual(finding['severity'], 'critical')  # xxe -> critical
        self.assertEqual(finding['url'], 'http://target/b2b/v2/')
        self.assertEqual(finding['parameter'], 'xml')
        self.assertFalse(finding['simulated'])
        self.assertEqual(finding['remote_address'], '203.0.113.9')

    def test_probe_without_matching_interaction_produces_no_finding(self):
        """Una sonda que NO tuvo interacción no debe aparecer en el
        resultado ni como 'confirmado' ni como ningún otro hallazgo --
        simplemente se omite (mismo criterio §2.1)."""
        mock_scanner = MagicMock()
        mock_scanner._last_oast_probes = [
            {'label': 'noanswer01', 'technique': 'ssrf',
             'url': 'http://target/x', 'parameter': 'id', 'method': 'GET'},
            {'label': 'hasanswer2', 'technique': 'command',
             'url': 'http://target/y', 'parameter': 'ip', 'method': 'POST'},
        ]
        o = _orchestrator(injection_scanner=mock_scanner)
        mock_session = MagicMock()
        mock_session.poll.return_value = [{
            'protocol': 'http', 'full-id': 'hasanswer2.correlationid.oast.pro',
        }]
        result = o.collect_oast_findings(mock_session)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]['parameter'], 'ip')  # solo la sonda con respuesta

    def test_severity_mapping_per_technique(self):
        mock_scanner = MagicMock()
        mock_scanner._last_oast_probes = [
            {'label': 'l1', 'technique': 'xxe', 'url': 'u1', 'parameter': 'p1', 'method': 'GET'},
            {'label': 'l2', 'technique': 'ssrf', 'url': 'u2', 'parameter': 'p2', 'method': 'GET'},
            {'label': 'l3', 'technique': 'command', 'url': 'u3', 'parameter': 'p3', 'method': 'GET'},
        ]
        o = _orchestrator(injection_scanner=mock_scanner)
        mock_session = MagicMock()
        mock_session.poll.return_value = [
            {'full-id': 'l1.c.oast.pro'}, {'full-id': 'l2.c.oast.pro'}, {'full-id': 'l3.c.oast.pro'},
        ]
        result = o.collect_oast_findings(mock_session)
        severities = {f['parameter']: f['severity'] for f in result}
        self.assertEqual(severities['p1'], 'critical')  # xxe
        self.assertEqual(severities['p2'], 'high')       # ssrf
        self.assertEqual(severities['p3'], 'critical')   # command

    def test_deregisters_session_even_when_interactions_found(self):
        mock_scanner = MagicMock()
        mock_scanner._last_oast_probes = [
            {'label': 'l1', 'technique': 'ssrf', 'url': 'u1', 'parameter': 'p1', 'method': 'GET'},
        ]
        o = _orchestrator(injection_scanner=mock_scanner)
        mock_session = MagicMock()
        mock_session.poll.return_value = [{'full-id': 'l1.c.oast.pro'}]
        o.collect_oast_findings(mock_session)
        mock_session.deregister.assert_called_once()

    def test_no_injection_scanner_available_returns_empty(self):
        """self.injection_scanner es None (módulo no disponible) --
        getattr() con default [] evita un AttributeError y el resultado es
        simplemente sin sondas que correlacionar."""
        o = _orchestrator(injection_scanner=None)
        mock_session = MagicMock()
        result = o.collect_oast_findings(mock_session)
        self.assertEqual(result, [])
        mock_session.deregister.assert_called_once()
        mock_session.poll.assert_not_called()


class TestRunInjectionScanSentinelFix(unittest.TestCase):
    """Regresión del tercer hallazgo del patrón §2.1 (encontrado como
    drive-by al instrumentar esta función para Fase 3, 2026-11-08): antes,
    un timeout o excepción en InjectionScanner.scan() devolvía un dict
    sentinela sin 'simulated' (p.ej. [{'error': ..., 'tool':
    'injection_scanner'}]) que scoring.py no filtraba y terminaba como
    hallazgo 'info' fabricado en el reporte. Ahora debe ser siempre []."""

    def _orchestrator_with_scanner(self, scan_side_effect):
        mock_scanner = MagicMock()
        mock_scanner.scan.side_effect = scan_side_effect
        o = _orchestrator(injection_scanner=mock_scanner)
        o.TIMEOUTS = {'injection': 5}
        return o

    def test_timeout_returns_empty_list_not_sentinel(self):
        o = self._orchestrator_with_scanner(ScanTimeoutError("timeout"))
        with patch('modules.pentesting.orchestrator.run_with_timeout',
                   side_effect=ScanTimeoutError("timeout")):
            result = o.run_injection_scan('http://target')
        self.assertEqual(result, [])

    def test_unexpected_exception_returns_empty_list_not_sentinel(self):
        o = self._orchestrator_with_scanner(RuntimeError("boom"))
        with patch('modules.pentesting.orchestrator.run_with_timeout',
                   side_effect=RuntimeError("boom")):
            result = o.run_injection_scan('http://target')
        self.assertEqual(result, [])

    def test_oast_canary_is_forwarded_to_injection_scanner_scan(self):
        mock_scanner = MagicMock()
        o = _orchestrator(injection_scanner=mock_scanner)
        o.TIMEOUTS = {'injection': 5}
        with patch('modules.pentesting.orchestrator.run_with_timeout') as mock_run:
            mock_run.return_value = []
            o.run_injection_scan('http://target', oast_canary='xyz.oast.pro')
        _, kwargs = mock_run.call_args
        self.assertEqual(kwargs['kwargs']['oast_canary'], 'xyz.oast.pro')

    def test_oast_canary_defaults_to_none_unchanged_behavior(self):
        mock_scanner = MagicMock()
        o = _orchestrator(injection_scanner=mock_scanner)
        o.TIMEOUTS = {'injection': 5}
        with patch('modules.pentesting.orchestrator.run_with_timeout') as mock_run:
            mock_run.return_value = []
            o.run_injection_scan('http://target')
        _, kwargs = mock_run.call_args
        self.assertIsNone(kwargs['kwargs']['oast_canary'])


if __name__ == '__main__':
    unittest.main()
