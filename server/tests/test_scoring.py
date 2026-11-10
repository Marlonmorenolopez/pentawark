"""
Pruebas unitarias para server/utils/scoring.py::calculate_security_score

Contexto (hallazgo de un reporte real de escaneo contra DVWA, aportado por el
usuario el 2026-10-14, confirmado al auditar scoring.py el 2026-10-15): el
score final mostraba breakdown critical:1/high:1/medium:3 mientras que los
conteos crudos de Metasploit para ese mismo scan eran critical:2/high:2/
medium:2 -- una discrepancia que no tenía una causa evidente a simple vista.

Causa raíz: calculate_security_score() deduplica hallazgos por la clave
(name, severity, tool), pero MetasploitScanner._make() construye cada
hallazgo con las claves 'title' y 'source' (no 'name'/'tool' como ZAP,
Nuclei e InjectionScanner). Al leer vuln.get('name', '') y
vuln.get('tool', ''), TODO hallazgo de Metasploit caía en la clave
('', severity, '') -- indistinguible de cualquier otro hallazgo de
Metasploit con la misma severidad. Así, "MSF Shellshock" (critical) y
"MSF Ms15 034 Http Sys Memory Dump" (critical) -- dos módulos distintos,
dos hallazgos reales y distintos -- se fundían en un solo item antes de
calcular el score, y lo mismo ocurría con los dos "high" y los dos "medium".
La Fase 2 (cap por tool+severidad) tenía el mismo problema: todos los
hallazgos de Metasploit caían en el bucket 'unknown' en vez de uno propio.

Estas pruebas fijan el comportamiento corregido: el nombre y la herramienta
de un hallazgo se leen con fallback a 'title'/'source' cuando 'name'/'tool'
no están presentes, de modo que hallazgos distintos de Metasploit con la
misma severidad ya no se fusionan artificialmente.

Ejecutar:
    cd server && python3 -m unittest tests.test_scoring -v
"""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))  # server/

from utils.scoring import calculate_security_score  # noqa: E402


def _msf_finding(title, severity, module, cvss=9.8):
    """Reproduce la forma exacta de MetasploitScanner._make(): usa
    'title'/'source', NUNCA 'name'/'tool'."""
    return {
        "title": title,
        "severity": severity,
        "cvss": cvss,
        "description": f"Host: dvwa | Port: 80/tcp | módulo {module}",
        "module": module,
        "host": "dvwa",
        "port": 80,
        "protocol": "tcp",
        "source": "metasploit",
        "simulated": False,
    }


class TestMetasploitFieldNamingRegression(unittest.TestCase):
    """Caso exacto observado en el reporte real del usuario."""

    def test_two_distinct_critical_metasploit_findings_are_not_merged(self):
        vulns = [
            _msf_finding("MSF Shellshock", "critical", "auxiliary/scanner/http/shellshock"),
            _msf_finding("MSF Ms15 034 Http Sys Memory Dump", "critical",
                         "auxiliary/scanner/http/ms15_034_http_sys_memory_dump"),
        ]
        score = calculate_security_score(vulns, exploits=[])
        self.assertEqual(
            score['breakdown']['critical'], 2,
            "Dos hallazgos distintos de Metasploit (títulos y módulos distintos) "
            "con la misma severidad NO deben fusionarse en uno solo por carecer "
            "de 'name'/'tool'.",
        )
        self.assertEqual(score['metrics']['totalVulnerabilities'], 2)

    def test_two_distinct_high_metasploit_findings_are_not_merged(self):
        vulns = [
            _msf_finding("MSF Http Version", "high", "auxiliary/scanner/http/http_version", cvss=7.5),
            _msf_finding("MSF Robots Txt", "high", "auxiliary/scanner/http/robots_txt", cvss=7.5),
        ]
        score = calculate_security_score(vulns, exploits=[])
        self.assertEqual(score['breakdown']['high'], 2)

    def test_two_distinct_medium_metasploit_findings_are_not_merged(self):
        vulns = [
            _msf_finding("MSF Options", "medium", "auxiliary/scanner/http/options", cvss=5.0),
            _msf_finding("MSF Dir Listing", "medium", "auxiliary/scanner/http/dir_listing", cvss=5.0),
        ]
        score = calculate_security_score(vulns, exploits=[])
        self.assertEqual(score['breakdown']['medium'], 2)

    def test_actually_duplicate_metasploit_finding_still_deduped(self):
        """La corrección no debe desactivar la deduplicación real: el mismo
        módulo reportado dos veces (mismo title/severity/source) sigue
        contando una sola vez."""
        same = _msf_finding("MSF Shellshock", "critical", "auxiliary/scanner/http/shellshock")
        vulns = [dict(same), dict(same)]
        score = calculate_security_score(vulns, exploits=[])
        self.assertEqual(score['breakdown']['critical'], 1)

    def test_zap_and_metasploit_findings_do_not_collide_via_empty_tool(self):
        """Antes de la corrección, un hallazgo de ZAP con name='' (si llegara
        a ocurrir) y uno de Metasploit podían compartir la clave ('', sev, '').
        Con el fallback a 'source', Metasploit ya no comparte bucket con
        hallazgos de otras herramientas por accidente."""
        vulns = [
            {"name": "Missing Anti-clickjacking Header", "severity": "medium", "tool": "OWASP ZAP"},
            _msf_finding("MSF Options", "medium", "auxiliary/scanner/http/options", cvss=5.0),
        ]
        score = calculate_security_score(vulns, exploits=[])
        self.assertEqual(score['breakdown']['medium'], 2)

    def test_real_report_scenario_matches_corrected_breakdown(self):
        """Reconstrucción del caso real: 6 hallazgos de Metasploit con
        severidades critical/critical/high/high/medium/medium, todos con
        título y módulo distintos. Antes de la corrección, el score los
        colapsaba a critical:1/high:1/medium:1 (bucket vacío compartido).
        Corregido, deben contarse los 6 como distintos."""
        vulns = [
            _msf_finding("MSF Shellshock", "critical", "auxiliary/scanner/http/shellshock"),
            _msf_finding("MSF Ms15 034 Http Sys Memory Dump", "critical",
                         "auxiliary/scanner/http/ms15_034_http_sys_memory_dump"),
            _msf_finding("MSF Http Version", "high", "auxiliary/scanner/http/http_version", cvss=7.5),
            _msf_finding("MSF Robots Txt", "high", "auxiliary/scanner/http/robots_txt", cvss=7.5),
            _msf_finding("MSF Options", "medium", "auxiliary/scanner/http/options", cvss=5.0),
            _msf_finding("MSF Dir Listing", "medium", "auxiliary/scanner/http/dir_listing", cvss=5.0),
        ]
        score = calculate_security_score(vulns, exploits=[])
        self.assertEqual(score['breakdown'], {
            'critical': 2, 'high': 2, 'medium': 2, 'low': 0, 'info': 0,
        })


class TestNameToolFallbackDoesNotBreakNormalFindings(unittest.TestCase):
    """Hallazgos con 'name'/'tool' normales (ZAP, Nuclei, InjectionScanner)
    deben comportarse exactamente igual que antes de la corrección."""

    def test_zap_style_findings_dedupe_as_before(self):
        vulns = [
            {"name": "X-Content-Type-Options Header Missing", "severity": "low", "tool": "OWASP ZAP"},
            {"name": "X-Content-Type-Options Header Missing", "severity": "low", "tool": "OWASP ZAP"},
            {"name": "Cookie without SameSite Attribute", "severity": "low", "tool": "OWASP ZAP"},
        ]
        score = calculate_security_score(vulns, exploits=[])
        self.assertEqual(score['breakdown']['low'], 2)

    def test_exploit_correlation_still_works_with_name_field(self):
        vulns = [{"name": "Apache 2.4.68 RCE", "severity": "high", "tool": "OWASP ZAP", "cvss": 7.5}]
        exploits = [{"matchedTerm": "apache", "cvss": 8.0}]
        score = calculate_security_score(vulns, exploits=exploits)
        self.assertEqual(score['exploitImpact']['correlatedExploits'], 1)


class TestSimulatedExploitsAndBruteForceMustBeFilteredBeforeScoring(unittest.TestCase):
    """
    Contexto (confirmado con un reporte real contra WebGoat, 2026-10-16):
    server/app.py, paso 'Scoring', ya excluía del score los hallazgos
    simulados de vulnerabilities/sqli_results/nuclei_findings/metasploit,
    pero pasaba 'exploits' y 'brute_force_results' SIN ese mismo filtro a
    calculate_security_score(). Searchsploit (`_simulate_scan` en
    searchsploit.py) y Patator (`_simulate_scan` en patator.py) pueden
    caer en modo simulado igual que cualquier otra herramienta, y sus
    datos de demostración (`simulated: true`) terminaban restando puntos
    reales al score -- en el caso de WebGoat, 2 exploits simulados
    restaron 6.0 puntos sin evidencia real de exploit público aplicable.

    calculate_security_score() en sí NO filtra por 'simulated' (nunca lo
    hizo, para vulnerabilities tampoco -- ese filtrado es responsabilidad
    de quien arma la lista antes de llamar la función, como ya hacía
    correctamente app.py para vulnerabilities). Estas pruebas documentan
    y fijan ese contrato: confirman que la función, dada una lista ya
    filtrada (como ahora produce app.py), no vuelve a contar lo simulado;
    la corrección real está en app.py, no aquí.
    """

    def test_simulated_exploit_excluded_before_scoring_has_no_penalty(self):
        simulated_exploits = [
            {"id": "51829", "title": "Apache Tomcat 9.0.x - AJP Request Injection",
             "severity": "critical", "matchedTerm": "Apache Tomcat",
             "tool": "searchsploit", "simulated": True},
        ]
        filtered = [e for e in simulated_exploits if not e.get('simulated', False)]
        score = calculate_security_score([], filtered)
        self.assertEqual(score['exploitImpact']['totalExploits'], 0)
        self.assertEqual(score['exploitImpact']['penalty'], 0)
        self.assertEqual(score['total'], 100)

    def test_real_exploit_counted_but_not_penalized_without_correlation(self):
        exploits = [
            {"id": "1", "title": "Real CVE", "severity": "critical",
             "matchedTerm": "Apache", "tool": "searchsploit", "simulated": False},
        ]
        filtered = [e for e in exploits if not e.get('simulated', False)]
        score = calculate_security_score([], filtered)
        self.assertEqual(score['exploitImpact']['totalExploits'], 1)
        self.assertEqual(score['exploitImpact']['penalty'], 0)
        self.assertEqual(score['exploitImpact']['correlatedExploits'], 0)

    def test_simulated_brute_force_excluded_before_scoring_has_no_penalty(self):
        simulated_bf = [{
            "name": "Credencial débil encontrada (admin/password)",
            "severity": "high", "credentials": [{"username": "admin", "password": "password"}],
            "attempts": 100, "success": True, "tool": "patator", "simulated": True,
        }]
        filtered = [b for b in simulated_bf if not b.get('simulated', False)]
        score = calculate_security_score([], [], brute_force_results=filtered)
        self.assertEqual(score['total'], 100)
        self.assertFalse(
            any('Credenciales débiles' in r for r in score['recommendations']),
            "Una credencial simulada/ficticia NUNCA debe generar la "
            "recomendación de 'credenciales débiles encontradas'.",
        )

    def test_real_brute_force_still_counted_after_filtering(self):
        real_bf = [{
            "name": "Credenciales débiles — 1 encontradas",
            "severity": "high", "credentials": [{"username": "admin", "password": "password"}],
            "attempts": 300, "success": True, "tool": "patator", "simulated": False,
        }]
        filtered = [b for b in real_bf if not b.get('simulated', False)]
        score = calculate_security_score([], [], brute_force_results=filtered)
        self.assertLess(score['total'], 100)
        self.assertTrue(any('Credenciales débiles' in r for r in score['recommendations']))


if __name__ == '__main__':
    unittest.main()
