"""
Pruebas unitarias para server/findings.py -- cobertura general del
módulo (no existía ningún test dedicado antes de la Fase 4, 2026-11,
autorizada por el usuario) y, en particular, de lo que esa Fase agregó:
`category`/`parameter` en el schema de Finding, la clave de fusión
extendida de `dedupe_findings()`, y `to_vulnerability_list()`.

Ejecutar:
    cd server && python3 -m unittest tests.test_findings -v
"""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))  # server/

import findings  # noqa: E402


class TestCategorize(unittest.TestCase):

    def test_injection_type_takes_priority(self):
        self.assertEqual(findings._categorize('sqlmap', 'algo raro', 'sql_union_based'), 'sqli')
        self.assertEqual(findings._categorize('injection_scanner', '', 'xxe'), 'xxe')
        self.assertEqual(findings._categorize('injection_scanner', '', 'ssrf'), 'ssrf')
        self.assertEqual(findings._categorize('injection_scanner', '', 'command_injection'), 'cmdi')
        self.assertEqual(findings._categorize('injection_scanner', '', 'ldap_injection'), 'ldap')

    def test_tool_based_category(self):
        self.assertEqual(findings._categorize('gitleaks', 'Secreto expuesto'), 'secrets')
        self.assertEqual(findings._categorize('trufflehog', 'algo'), 'secrets')
        self.assertEqual(findings._categorize('xposedornot', 'algo'), 'breach')
        self.assertEqual(findings._categorize('username_search', 'algo'), 'osint_identity')

    def test_keyword_fallback(self):
        self.assertEqual(findings._categorize('zap', 'SQL Injection detected'), 'sqli')
        self.assertEqual(findings._categorize('zap', 'Reflected Cross-Site Scripting (XSS)'), 'xss')
        self.assertEqual(findings._categorize('nuclei', 'CSRF token missing'), 'csrf')
        self.assertEqual(findings._categorize('nuclei', 'Expired TLS certificate'), 'tls')

    def test_no_match_returns_empty_string_never_raises(self):
        self.assertEqual(findings._categorize('', '', ''), '')
        self.assertEqual(findings._categorize('zap', 'Something completely generic', ''), '')
        self.assertEqual(findings._categorize(None, None, None), '')


class TestFromWeb(unittest.TestCase):

    def test_oast_findings_included_in_normalize(self):
        """Fase 4: antes de esta fase, normalize_findings() ignoraba por
        completo 'oast_findings' (Fase 3) -- ahora los incluye."""
        scan = {
            'scan_type': 'web',
            'oast_findings': [{
                'name': 'SSRF ciego confirmado (OAST)', 'severity': 'high',
                'tool': 'interactsh', 'url': 'http://target/x', 'parameter': 'id',
                'description': 'Interacción DNS real confirmada', 'simulated': False,
            }],
        }
        result = findings.normalize_findings(scan)
        self.assertEqual(len(result), 1)
        f = result[0]
        self.assertEqual(f['tool'], 'interactsh')
        self.assertEqual(f['category'], 'ssrf')
        self.assertEqual(f['parameter'], 'id')
        self.assertEqual(f['target'], 'http://target/x')

    def test_sqli_results_from_injection_scanner_gets_category_from_injection_type(self):
        scan = {
            'scan_type': 'web',
            'sqli_results': [{
                'tool': 'injection_scanner', 'name': 'XXE ciega',
                'injection_type': 'xxe', 'url': 'http://t/b2b', 'parameter': 'xml',
                'severity': 'critical',
            }],
        }
        result = findings.normalize_findings(scan)
        self.assertEqual(result[0]['category'], 'xxe')
        self.assertEqual(result[0]['parameter'], 'xml')

    def test_sqlmap_result_without_injection_type_falls_back_to_keywords(self):
        scan = {
            'scan_type': 'web',
            'sqli_results': [{
                'tool': 'sqlmap', 'parameter': 'id', 'url': 'http://t/login',
                'severity': 'critical',
                # Sin 'name' -- se arma como "SQL Injection: {parameter}"
            }],
        }
        result = findings.normalize_findings(scan)
        self.assertEqual(result[0]['category'], 'sqli')

    def test_vulnerabilities_parameter_passthrough(self):
        scan = {'scan_type': 'web', 'vulnerabilities': [
            {'tool': 'zap', 'name': 'SQL Injection', 'url': 'http://t/x', 'parameter': 'q', 'severity': 'high'},
        ]}
        result = findings.normalize_findings(scan)
        self.assertEqual(result[0]['parameter'], 'q')


class TestDedupeFindingsCveTargetUnchanged(unittest.TestCase):
    """El criterio original (cve+target) no debe cambiar de comportamiento."""

    def test_same_cve_and_target_merges_across_tools(self):
        a = findings._finding('a', 'nuclei', 'web', 'Log4Shell', 'critical',
                              target='http://t/', cve='CVE-2021-44228')
        b = findings._finding('b', 'zap', 'web', 'Apache Log4j RCE', 'high',
                              target='http://t/', cve='CVE-2021-44228')
        result = findings.dedupe_findings([a, b])
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]['tool'], 'nuclei + zap')
        self.assertEqual(result[0]['severity'], 'critical')  # la más alta de las dos

    def test_different_target_does_not_merge(self):
        a = findings._finding('a', 'nuclei', 'web', 'X', 'high', target='http://a/', cve='CVE-1')
        b = findings._finding('b', 'zap', 'web', 'X', 'high', target='http://b/', cve='CVE-1')
        result = findings.dedupe_findings([a, b])
        self.assertEqual(len(result), 2)


class TestDedupeFindingsCategoryExtension(unittest.TestCase):
    """Fase 4: la nueva clave de fusión (category, target, parameter) --
    cubre el caso sin CVE que el criterio original nunca cubrió."""

    def test_same_category_target_parameter_merges_across_tools(self):
        """Dos motores distintos (ZAP e InjectionScanner) reportan SQLi
        sobre el MISMO endpoint+parámetro, sin CVE -- antes de la Fase 4
        esto NUNCA se fusionaba (dedupe_findings exigía cve+target)."""
        zap = findings._finding('a', 'zap', 'web', 'SQL Injection', 'high',
                                target='http://t/login', parameter='user')
        scanner = findings._finding('b', 'injection_scanner', 'web', 'SQLi confirmada', 'critical',
                                    target='http://t/login', parameter='user', injection_type='sql_union_based')
        result = findings.dedupe_findings([zap, scanner])
        self.assertEqual(len(result), 1)
        self.assertIn('zap', result[0]['tool'])
        self.assertIn('injection_scanner', result[0]['tool'])
        self.assertEqual(result[0]['severity'], 'critical')

    def test_same_category_target_but_different_parameter_does_not_merge(self):
        """Mismo endpoint, PARÁMETRO distinto -- son hallazgos distintos
        (dos puntos de inyección separados), no deben fusionarse."""
        a = findings._finding('a', 'zap', 'web', 'SQL Injection', 'high',
                              target='http://t/login', parameter='user')
        b = findings._finding('b', 'zap', 'web', 'SQL Injection', 'high',
                              target='http://t/login', parameter='password')
        result = findings.dedupe_findings([a, b])
        self.assertEqual(len(result), 2)

    def test_different_category_same_target_does_not_merge(self):
        """Mismo endpoint, categorías DISTINTAS (SQLi vs XSS) -- no se
        fusionan, son vulnerabilidades distintas."""
        a = findings._finding('a', 'zap', 'web', 'SQL Injection', 'high', target='http://t/x', parameter='q')
        b = findings._finding('b', 'zap', 'web', 'Reflected XSS', 'medium', target='http://t/x', parameter='q')
        result = findings.dedupe_findings([a, b])
        self.assertEqual(len(result), 2)

    def test_empty_category_never_merges_falsely(self):
        """Dos hallazgos sin categoría inferible (título genérico, sin
        CVE) -- nunca se fusionan por accidente bajo una clave vacía
        compartida (sería fusionar cosas no relacionadas)."""
        a = findings._finding('a', 'metasploit', 'web', 'MSF Shellshock', 'critical', target='http://t/')
        b = findings._finding('b', 'metasploit', 'web', 'MSF Ms15 034', 'critical', target='http://t/')
        result = findings.dedupe_findings([a, b])
        self.assertEqual(len(result), 2)

    def test_cve_target_takes_priority_over_category_key(self):
        """Si un hallazgo tiene cve+target Y category, se fusiona por
        cve+target (prioridad 1), no por category -- sin cambios de
        comportamiento respecto al criterio original."""
        a = findings._finding('a', 'nuclei', 'web', 'SQL Injection', 'high',
                              target='http://t/x', cve='CVE-2024-1', parameter='q')
        b = findings._finding('b', 'zap', 'web', 'SQL Injection', 'critical',
                              target='http://t/x', cve='CVE-2024-1', parameter='q')
        result = findings.dedupe_findings([a, b])
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]['cve'], 'CVE-2024-1')


class TestToVulnerabilityList(unittest.TestCase):

    def test_round_trips_raw_with_merged_tool_and_severity(self):
        raw_a = {'name': 'SQL Injection', 'severity': 'high', 'tool': 'zap',
                 'url': 'http://t/login', 'parameter': 'user'}
        raw_b = {'name': 'SQLi confirmada', 'severity': 'critical', 'tool': 'injection_scanner',
                 'url': 'http://t/login', 'parameter': 'user', 'injection_type': 'sql_union_based'}
        scan = {'scan_type': 'web', 'vulnerabilities': [raw_a],
                'sqli_results': [raw_b]}
        deduped = findings.dedupe_findings(findings.normalize_findings(scan))
        vulns = findings.to_vulnerability_list(deduped)
        self.assertEqual(len(vulns), 1)
        self.assertIn('zap', vulns[0]['tool'])
        self.assertIn('injection_scanner', vulns[0]['tool'])
        self.assertEqual(vulns[0]['severity'], 'critical')
        # El resto de los campos del raw original se conservan (p.ej. 'url').
        self.assertEqual(vulns[0]['url'], 'http://t/login')

    def test_findings_without_raw_are_skipped_not_fabricated(self):
        f = findings._finding('a', 'zap', 'web', 'X', 'high', target='http://t/', raw=None)
        self.assertEqual(findings.to_vulnerability_list([f]), [])

    def test_unmerged_findings_pass_through_unchanged_shape(self):
        raw = {'title': 'MSF Shellshock', 'severity': 'critical', 'source': 'metasploit', 'host': 'http://t/'}
        scan = {'scan_type': 'web', 'metasploit': [raw]}
        deduped = findings.dedupe_findings(findings.normalize_findings(scan))
        vulns = findings.to_vulnerability_list(deduped)
        self.assertEqual(len(vulns), 1)
        self.assertEqual(vulns[0]['tool'], 'metasploit')
        self.assertEqual(vulns[0]['title'], 'MSF Shellshock')  # campo original intacto


if __name__ == '__main__':
    unittest.main()
