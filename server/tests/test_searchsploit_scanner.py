"""
Pruebas unitarias para:
  - server/modules/pentesting/searchsploit.py           (SearchsploitSearcher)
  - server/modules/pentesting/orchestrator.py::search_exploits()

Contexto (auditoría de Pentesting, 2026-10-16, continuación de
§2.1/§6.5/§6.6/§6.7/gobuster/ffuf/patator):

Defecto 1 (patrón §2.1, ya corregido 3 veces en nmap_scanner/wappalyzer/
nuclei): `SearchsploitSearcher.search()` -- tras confirmar que la
herramienta SÍ está disponible y SÍ corrió (`self._available` ya filtrado
arriba) -- caía en `_simulate_search()` cuando `all_exploits` quedaba
vacío. Pero 0 resultados tras una búsqueda real es un resultado honesto:
ExploitDB simplemente no tiene exploits para esos términos. Fabricar
exploits (Apache Tomcat AJP Injection, PHP backdoor, MySQL RCE, etc.,
'simulated': True) presentaba una búsqueda real sin resultados como si
hubiera encontrado algo. Esto explica directamente la evidencia ya
analizada en §6.7: un reporte real de WebGoat donde Searchsploit simulado
aportó 2 exploits ficticios que restaban puntos reales al score. Corregido
para devolver `[]`.

Defecto 2 (mismo patrón, en la capa orchestrator -- igual que
run_gobuster()/run_ffuf()): `search_exploits()` en sus `except
ScanTimeoutError`/`except Exception` devolvía `[{'error': ...}]` -- un
sentinel SIN 'simulated': True. Impacto confirmado peor que en
gobuster/ffuf porque SÍ llega a afectar el score real:
  1) app.py (paso Scoring) filtra `exploits` por `not e.get('simulated',
     False)` -- el sentinel pasa el filtro (no tiene esa clave) y entra a
     calculate_security_score() como si fuera un exploit real.
  2) En scoring.py, `e.get('matchedTerm', '')` da '' -> nunca correlaciona
     con ninguna vulnerabilidad -> cae en `exploit_without_vuln` -> resta
     puntos del score por un timeout, no por un hallazgo real.
  3) lib/scan-extractors.ts cuenta `s.exploits?.length ?? 0` sin filtrar
     -- se contaba como "1 exploit" en el panel de herramientas.
Corregido para devolver `[]`, igual que gobuster/ffuf.

Ejecutar:
    cd server && python3 -m unittest tests.test_searchsploit_scanner -v
"""

import json
import subprocess
import sys
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))  # server/

from modules.pentesting.searchsploit import SearchsploitSearcher  # noqa: E402
from modules.pentesting.orchestrator import (                      # noqa: E402
    SecurityOrchestrator, ScanTimeoutError,
)


def _scanner(available=True):
    s = SearchsploitSearcher.__new__(SearchsploitSearcher)
    s.command = 'searchsploit'
    s.timeout = 30
    s.max_results = 50
    s._available = available
    s._db_path = None
    return s


class TestSearchNeverFabricatesOnZeroRealResults(unittest.TestCase):
    """Regresión del defecto principal: una búsqueda real que corrió
    exitosamente pero no encontró coincidencias debe devolver [], nunca
    datos de _simulate_search()."""

    def test_zero_matches_from_real_search_returns_empty_list(self):
        s = _scanner(available=True)
        with patch.object(s, '_search_term', return_value=[]):
            result = s.search(['nonexistent-product-xyz'])
        self.assertEqual(
            result, [],
            "0 coincidencias reales de searchsploit debe ser [], no "
            "exploits simulados.",
        )

    def test_zero_matches_does_not_call_simulate_search(self):
        s = _scanner(available=True)
        with patch.object(s, '_search_term', return_value=[]), \
             patch.object(s, '_simulate_search') as mock_sim:
            s.search(['nonexistent-product-xyz'])
        mock_sim.assert_not_called()

    def test_binary_not_available_still_uses_simulation(self):
        """Caso legítimo de simulación: la herramienta NO está disponible."""
        s = _scanner(available=False)
        result = s.search(['apache'], technologies=[{'name': 'Apache Tomcat'}])
        self.assertTrue(len(result) >= 1)
        self.assertTrue(all(r.get('simulated') is True for r in result))

    def test_real_matches_are_returned_unsimulated(self):
        s = _scanner(available=True)
        fake_exploit = {
            'id': '12345', 'title': 'Fake Product 1.0 - RCE', 'date': '2024-01-01',
            'author': 'tester', 'type': 'remote', 'platform': 'linux',
            'path': '/opt/exploitdb/exploits/linux/remote/12345.py',
            'severity': 'high', 'url': 'https://www.exploit-db.com/exploits/12345',
            'matchedTerm': 'fake-product', 'tool': 'searchsploit', 'simulated': False,
        }
        with patch.object(s, '_search_term', return_value=[fake_exploit]):
            result = s.search(['fake-product'])
        self.assertEqual(len(result), 1)
        self.assertFalse(result[0]['simulated'])

    def test_empty_terms_returns_empty_list_without_searching(self):
        s = _scanner(available=True)
        with patch.object(s, '_search_term') as mock_search:
            result = s.search([''])
        self.assertEqual(result, [])
        mock_search.assert_not_called()


class TestCleanTerms(unittest.TestCase):

    def setUp(self):
        self.scanner = _scanner()

    def test_deduplicates_case_insensitively(self):
        result = self.scanner._clean_terms(['Apache', 'apache', 'APACHE'])
        self.assertEqual(result, ['Apache'])

    def test_filters_skip_terms(self):
        result = self.scanner._clean_terms(['python', 'nginx', 'json'])
        self.assertEqual(result, ['nginx'])

    def test_strips_shell_metacharacters(self):
        result = self.scanner._clean_terms(['apache; rm -rf /'])
        self.assertEqual(result, ['apache rm -rf /'])

    def test_rejects_too_short_or_too_long(self):
        result = self.scanner._clean_terms(['a', 'x' * 61, 'valid-term'])
        self.assertEqual(result, ['valid-term'])

    def test_empty_or_none_terms_skipped(self):
        result = self.scanner._clean_terms(['', None, 'nginx'])
        self.assertEqual(result, ['nginx'])


class TestSearchTermParsing(unittest.TestCase):
    """Verifica el parseo real de `searchsploit --json` (Popen +
    communicate), incluyendo el manejo de timeout SIGPIPE-safe."""

    def setUp(self):
        self.scanner = _scanner(available=True)

    def _mock_popen(self, stdout, returncode=0):
        proc = MagicMock()
        proc.communicate.return_value = (stdout, '')
        proc.returncode = returncode
        return proc

    def test_parses_results_exploit_and_maps_severity(self):
        fake_output = json.dumps({
            'RESULTS_EXPLOIT': [
                {'EDB-ID': '111', 'Title': 'Test Webapp RCE', 'Date': '2024-01-01',
                 'Author': 'x', 'Type': 'webapps', 'Platform': 'php', 'Path': '/p/111'},
            ],
            'RESULTS_SHELLCODE': [],
        })
        with patch('modules.pentesting.searchsploit.subprocess.Popen',
                   return_value=self._mock_popen(fake_output)):
            result = self.scanner._search_term('test')
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]['id'], '111')
        self.assertEqual(result[0]['severity'], 'high')  # webapps -> high
        self.assertFalse(result[0]['simulated'])

    def test_empty_stdout_returns_empty_list(self):
        with patch('modules.pentesting.searchsploit.subprocess.Popen',
                   return_value=self._mock_popen('', returncode=0)):
            result = self.scanner._search_term('test')
        self.assertEqual(result, [])

    def test_nonzero_nonone_returncode_returns_empty_list(self):
        with patch('modules.pentesting.searchsploit.subprocess.Popen',
                   return_value=self._mock_popen('{}', returncode=2)):
            result = self.scanner._search_term('test')
        self.assertEqual(result, [])

    def test_invalid_json_returns_empty_list_not_exception(self):
        with patch('modules.pentesting.searchsploit.subprocess.Popen',
                   return_value=self._mock_popen('not valid json', returncode=0)):
            result = self.scanner._search_term('test')
        self.assertEqual(result, [])

    def test_timeout_kills_process_and_returns_empty_list(self):
        proc = MagicMock()
        proc.communicate.side_effect = [
            subprocess.TimeoutExpired(cmd='searchsploit', timeout=30),
            ('', ''),  # segunda llamada tras kill(), para drenar pipes
        ]
        with patch('modules.pentesting.searchsploit.subprocess.Popen', return_value=proc):
            result = self.scanner._search_term('test')
        self.assertEqual(result, [])
        proc.kill.assert_called_once()


class TestOrchestratorSearchExploitsNeverFabricatesOnFailure(unittest.TestCase):
    """Regresión del defecto 2: search_exploits() en timeout/error debe
    devolver [], nunca un sentinel sin 'simulated' que contamine el score
    y el conteo del panel de herramientas."""

    def setUp(self):
        self.orchestrator = SecurityOrchestrator()

    def test_timeout_returns_empty_list(self):
        with patch.object(self.orchestrator.searchsploit, 'search',
                           side_effect=ScanTimeoutError('searchsploit timeout')):
            result = self.orchestrator.search_exploits(
                technologies=[{'name': 'Apache'}], ports=[], target='http://example.test')
        self.assertEqual(result, [])

    def test_generic_exception_returns_empty_list(self):
        with patch.object(self.orchestrator.searchsploit, 'search',
                           side_effect=RuntimeError('boom')):
            result = self.orchestrator.search_exploits(
                technologies=[{'name': 'Apache'}], ports=[], target='http://example.test')
        self.assertEqual(result, [])

    def test_no_terms_and_unknown_target_returns_empty_list(self):
        result = self.orchestrator.search_exploits(
            technologies=[], ports=[], target='http://totally-unknown-lab.test')
        self.assertEqual(result, [])

    def test_successful_search_is_passed_through(self):
        fake = [{'id': '1', 'title': 'x', 'simulated': False}]
        with patch.object(self.orchestrator.searchsploit, 'search', return_value=fake):
            result = self.orchestrator.search_exploits(
                technologies=[{'name': 'Apache'}], ports=[], target='http://example.test')
        self.assertEqual(result, fake)


if __name__ == '__main__':
    unittest.main()
