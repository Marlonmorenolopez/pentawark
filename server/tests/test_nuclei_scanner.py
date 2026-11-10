"""
Pruebas unitarias para server/modules/pentesting/nuclei.py (NucleiScanner)

Contexto (auditoría de cobertura de vulnerabilidades, 2026-11, Fase 0 del
plan de implementación acordado con el usuario tras la auditoría de solo
lectura): se identificó que nuclei.py seguía teniendo el patrón §2.1 ya
corregido en los otros 9 módulos de la auditoría anterior
(AUDIT_PENTESTING.md) -- scan() sustituía "0 hallazgos reales" (y también
timeout/excepción genérica) por datos fabricados de _simulate(), que
devuelve CVEs y hallazgos fijos por laboratorio marcados `simulated: True`
pero con la misma forma que un hallazgo real.

Corregido:
  - 0 hallazgos reales (corrida exitosa, sin excepción) -> [] (antes:
    _simulate()).
  - subprocess.TimeoutExpired -> [] (antes: _simulate()), mismo criterio ya
    aplicado a sqlmap.py/ffuf.py/gobuster.py/zap_scanner.py/searchsploit.py:
    un timeout no es "herramienta no disponible".
  - Exception genérica -> [] (antes: _simulate()).
  - FileNotFoundError (binario desaparece entre el chequeo de
    self._available y la ejecución) SÍ sigue siendo un caso legítimo de
    simulación -- es la misma condición de "herramienta ausente" que ya
    cubre `self._available` más arriba en scan().

Ejecutar:
    cd server && python3 -m unittest tests.test_nuclei_scanner -v
"""

import subprocess
import sys
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))  # server/

from modules.pentesting.nuclei import NucleiScanner  # noqa: E402


def _scanner(available=True):
    s = NucleiScanner.__new__(NucleiScanner)
    s.timeout = 60
    s.severity = 'info,low,medium,high,critical'
    s.command = 'nuclei'
    s._available = available
    s._tpl_path = '/home/scanner/nuclei-templates'
    s._nuclei_ver = '3.2.4'
    return s


def _run_scan(scanner, target='http://dvwa:80', *, run_side_effect=None,
              parsed_findings=None):
    """Corre scan() con _validate_target/_check_connectivity simulando un
    target válido y alcanzable (el caso real observado: nuclei sí corrió),
    y con subprocess.run controlado por el caller."""
    with patch.object(NucleiScanner, '_validate_target', return_value=(True, target)), \
         patch.object(NucleiScanner, '_check_connectivity', return_value=True), \
         patch.object(NucleiScanner, '_detect_target_type', return_value='dvwa'), \
         patch.object(NucleiScanner, '_get_tags', return_value=['sqli', 'xss']), \
         patch.object(NucleiScanner, '_build_cmd', return_value=['nuclei', '-u', target]), \
         patch('modules.pentesting.nuclei.tempfile.NamedTemporaryFile'), \
         patch('modules.pentesting.nuclei.tempfile.mkstemp', return_value=(99, '/tmp/fake.jsonl')), \
         patch('modules.pentesting.nuclei.os.close'), \
         patch('modules.pentesting.nuclei.os.path.exists', return_value=False), \
         patch('modules.pentesting.nuclei.os.unlink'), \
         patch.object(NucleiScanner, '_parse_jsonl', return_value=parsed_findings if parsed_findings is not None else []):
        if run_side_effect is not None:
            with patch('modules.pentesting.nuclei.subprocess.run', side_effect=run_side_effect):
                return scanner.scan(target)
        else:
            mock_proc = MagicMock(returncode=0, stdout='', stderr='')
            with patch('modules.pentesting.nuclei.subprocess.run', return_value=mock_proc):
                return scanner.scan(target)


class TestZeroFindingsNeverFabricates(unittest.TestCase):
    """Regresión del defecto principal: 0 hallazgos reales tras una corrida
    exitosa (sin excepción) debe ser [], nunca los datos fijos de
    _simulate()."""

    def test_zero_real_findings_returns_empty_list_not_simulated(self):
        scanner = _scanner(available=True)
        with patch.object(scanner, '_simulate') as mock_simulate:
            result = _run_scan(scanner, parsed_findings=[])
        self.assertEqual(result, [])
        mock_simulate.assert_not_called()

    def test_real_finding_is_still_returned(self):
        scanner = _scanner(available=True)
        real = {'template_id': 'exposed-readme', 'name': 'README.md Exposed',
                'severity': 'info', 'url': 'http://dvwa:80/README.md',
                'tags': ['exposure'], 'references': [], 'tool': 'nuclei',
                'simulated': False}
        with patch.object(scanner, '_simulate') as mock_simulate:
            result = _run_scan(scanner, parsed_findings=[real])
        self.assertEqual(result, [real])
        mock_simulate.assert_not_called()


class TestTimeoutAndGenericExceptionNeverFabricate(unittest.TestCase):

    def test_timeout_returns_empty_list_not_simulated(self):
        scanner = _scanner(available=True)
        with patch.object(scanner, '_simulate') as mock_simulate:
            result = _run_scan(
                scanner,
                run_side_effect=subprocess.TimeoutExpired(cmd='nuclei', timeout=60),
            )
        self.assertEqual(
            result, [],
            "Un timeout real de nuclei no debe producir datos simulados -- "
            "no es evidencia de que la herramienta esté ausente.",
        )
        mock_simulate.assert_not_called()

    def test_generic_exception_returns_empty_list_not_simulated(self):
        scanner = _scanner(available=True)
        with patch.object(scanner, '_simulate') as mock_simulate:
            result = _run_scan(scanner, run_side_effect=RuntimeError('boom'))
        self.assertEqual(result, [])
        mock_simulate.assert_not_called()


class TestLegitimateSimulationPathsUnchanged(unittest.TestCase):
    """Los dos únicos casos legítimos de simulación (herramienta
    genuinamente ausente) deben seguir devolviendo _simulate()."""

    def test_binary_not_available_at_start_still_simulates(self):
        scanner = _scanner(available=False)
        with patch.object(NucleiScanner, '_validate_target', return_value=(True, 'http://dvwa:80')), \
             patch.object(NucleiScanner, '_check_connectivity', return_value=True), \
             patch.object(NucleiScanner, '_detect_target_type', return_value='dvwa'), \
             patch.object(NucleiScanner, '_get_tags', return_value=['sqli']), \
             patch.object(scanner, '_simulate', return_value=[{'simulated': True}]) as mock_simulate:
            result = scanner.scan('http://dvwa:80')
        mock_simulate.assert_called_once()
        self.assertEqual(result, [{'simulated': True}])

    def test_binary_disappears_mid_scan_still_simulates(self):
        scanner = _scanner(available=True)
        with patch.object(scanner, '_simulate', return_value=[{'simulated': True}]) as mock_simulate:
            result = _run_scan(scanner, run_side_effect=FileNotFoundError())
        mock_simulate.assert_called_once()
        self.assertEqual(result, [{'simulated': True}])


if __name__ == '__main__':
    unittest.main()
