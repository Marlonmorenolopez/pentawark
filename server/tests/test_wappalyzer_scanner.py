"""
Pruebas unitarias para server/modules/pentesting/wappalyzer.py (WappalyzerScanner)

Contexto (auditoría de cobertura de vulnerabilidades, 2026-11, Fase 0 del
plan de implementación acordado con el usuario tras la auditoría de solo
lectura): se identificó que la cascada lib -> CLI -> _simulate_scan() de
scan() no distinguía "la librería/CLI corrió con éxito y detectó 0
tecnologías reales" (resultado honesto, posible contra una página sin
huellas reconocibles) de "no se pudo ejecutar en absoluto" -- ambos casos
producían una lista vacía `[]`, y `if result:` trataba ambos como falsy,
cayendo en cascada hasta _simulate_scan(), que fabrica tecnologías fijas
por laboratorio (Node.js/Express/Angular para Juice Shop, Apache/PHP/MySQL
para DVWA, etc.) marcadas `simulated: True` pero indistinguibles en forma
de un hallazgo real.

Corregido: _scan_with_lib()/_scan_with_cli() ahora devuelven `None` cuando
NO pudieron ejecutarse (excepción, CLI sin salida utilizable) y una lista
(incluso vacía) cuando sí corrieron. scan() solo continúa la cascada ante
`None` -- una lista vacía real se respeta y se devuelve tal cual, sin
pasar por _simulate_scan().

Ejecutar:
    cd server && python3 -m unittest tests.test_wappalyzer_scanner -v
"""

import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))  # server/

from modules.pentesting.wappalyzer import WappalyzerScanner  # noqa: E402
from modules.pentesting.orchestrator import (                 # noqa: E402
    SecurityOrchestrator, ScanTimeoutError,
)


def _scanner(lib_available=True, cli_available=False):
    s = WappalyzerScanner.__new__(WappalyzerScanner)
    s.timeout = 60
    s.command = 'wappalyzer'
    s._cli_available = cli_available
    s._lib_available = lib_available
    s._wappalyzer_instance = None
    return s


class TestLibZeroRealResultsNeverFabricates(unittest.TestCase):
    """Regresión del defecto principal: la librería corre con éxito y
    detecta 0 tecnologías reales -- debe ser [], nunca los datos fijos de
    _simulate_scan()."""

    def test_lib_zero_findings_returns_empty_list_not_simulated(self):
        scanner = _scanner(lib_available=True, cli_available=False)
        with patch.object(scanner, '_scan_with_lib', return_value=[]) as mock_lib, \
             patch.object(scanner, '_simulate_scan') as mock_sim:
            result = scanner.scan('http://dvwa:80')
        mock_lib.assert_called_once()
        mock_sim.assert_not_called()
        self.assertEqual(result, [])

    def test_lib_real_findings_are_returned(self):
        scanner = _scanner(lib_available=True, cli_available=False)
        techs = [{'name': 'Apache', 'version': '2.4.68', 'category': 'server',
                  'confidence': 100, 'description': 'desc', 'simulated': False}]
        with patch.object(scanner, '_scan_with_lib', return_value=techs), \
             patch.object(scanner, '_simulate_scan') as mock_sim:
            result = scanner.scan('http://dvwa:80')
        mock_sim.assert_not_called()
        self.assertEqual(result, techs)

    def test_lib_exception_falls_through_to_cli_then_simulation(self):
        """Cuando la librería SÍ falla (None), la cascada hacia CLI/
        simulación debe seguir funcionando como antes."""
        scanner = _scanner(lib_available=True, cli_available=True)
        with patch.object(scanner, '_scan_with_lib', return_value=None), \
             patch.object(scanner, '_scan_with_cli', return_value=None) as mock_cli, \
             patch.object(scanner, '_simulate_scan', return_value=[{'simulated': True}]) as mock_sim:
            result = scanner.scan('http://dvwa:80')
        mock_cli.assert_called_once()
        mock_sim.assert_called_once()
        self.assertEqual(result, [{'simulated': True}])

    def test_lib_fails_cli_has_real_zero_results_not_simulated(self):
        """Si la librería falla (None) pero el CLI sí corre y encuentra 0
        reales ([]), tampoco debe caer a simulación."""
        scanner = _scanner(lib_available=True, cli_available=True)
        with patch.object(scanner, '_scan_with_lib', return_value=None), \
             patch.object(scanner, '_scan_with_cli', return_value=[]) as mock_cli, \
             patch.object(scanner, '_simulate_scan') as mock_sim:
            result = scanner.scan('http://dvwa:80')
        mock_cli.assert_called_once()
        mock_sim.assert_not_called()
        self.assertEqual(result, [])


class TestNeitherAvailableStillSimulates(unittest.TestCase):
    """Único caso legítimo de simulación: ni la librería ni el CLI están
    disponibles en absoluto."""

    def test_neither_available_simulates(self):
        scanner = _scanner(lib_available=False, cli_available=False)
        with patch.object(scanner, '_simulate_scan', return_value=[{'simulated': True}]) as mock_sim:
            result = scanner.scan('http://dvwa:80')
        mock_sim.assert_called_once()
        self.assertEqual(result, [{'simulated': True}])


class TestOrchestratorRunWappalyzerNeverFabricatesOnFailure(unittest.TestCase):
    """Regresión (auditoría pentesting, hallazgo documentado en §6.11,
    corregido 2026-11-07): orchestrator.run_wappalyzer() devolvía, en
    timeout/excepción, [{'error': ...}] -- un item sin 'name'/'severity'/
    'tool'/'simulated'. scoring.py no lo excluía del score exportado
    (termina como hallazgo 'info' con nombre vacío). Mismo criterio §2.1
    ya aplicado en ffuf/gobuster/nuclei/zap/sqlmap/searchsploit/patator/
    injection_scanner/testssl/nmap: sin datos reales, lista vacía."""

    def setUp(self):
        self.orchestrator = SecurityOrchestrator()

    def test_timeout_returns_empty_list_not_bare_error_item(self):
        with patch.object(self.orchestrator.wappalyzer, 'scan',
                           side_effect=ScanTimeoutError('wappalyzer timeout')):
            result = self.orchestrator.run_wappalyzer('http://dvwa:80')
        self.assertEqual(result, [])

    def test_generic_exception_returns_empty_list(self):
        with patch.object(self.orchestrator.wappalyzer, 'scan',
                           side_effect=RuntimeError('boom')):
            result = self.orchestrator.run_wappalyzer('http://dvwa:80')
        self.assertEqual(result, [])


if __name__ == '__main__':
    unittest.main()
