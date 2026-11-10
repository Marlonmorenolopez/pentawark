"""
Pruebas unitarias para server/modules/pentesting/metasploit.py::_parse_output

Contexto (hallazgo de un reporte real de escaneo contra DVWA, aportado por
el usuario el 2026-10-14): MetasploitScanner._parse_output() agregaba un
"hallazgo" por CADA módulo ejecutado, incluso cuando el módulo corría
limpio y no encontraba ninguna evidencia de la vulnerabilidad que verifica.
En ese caso usaba `default_sev` -- la severidad que el módulo tendría SI
confirmara el problema -- en vez de reflejar que no se encontró nada.

Evidencia real observada en el reporte del usuario (scan contra un
contenedor DVWA, Debian + Apache + PHP):
  - "MSF Shellshock" (auxiliary/scanner/http/shellshock, default_sev='critical')
    reportado como hallazgo CRÍTICO con descripción "Auxiliary module
    execution completed" -- sin ningún patrón positivo en la salida.
  - "MSF Ms15 034 Http Sys Memory Dump" (vulnerabilidad de Windows HTTP.sys)
    reportado igual como CRÍTICO contra un host Linux, lo cual no tiene
    sentido técnico -- el módulo evidentemente no encontró nada (el target
    ni siquiera es Windows) pero igual se reportó como hallazgo crítico.
  - "MSF Options" / "MSF Dir Listing" reportados en severidad 'medium' con
    la misma descripción genérica de "módulo completado", sin evidencia.

Estas pruebas fijan el comportamiento corregido: la ausencia de un patrón
positivo en la salida de msfconsole SIEMPRE se reporta en severidad
'info' para los módulos de verificación de vulnerabilidad (default_sev
distinto de 'info'), dejando explícito que no hay evidencia -- nunca se
hereda la severidad "si lo encontrara" del módulo. Los módulos puramente
informativos (default_sev == 'info') mantienen su comportamiento original.

Ejecutar:
    cd server && python3 -m unittest tests.test_metasploit_scanner -v
"""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))  # server/

from modules.pentesting.metasploit import MetasploitScanner  # noqa: E402


def _scanner():
    """Instancia sin intentar conectar a un msfrpcd real."""
    s = MetasploitScanner.__new__(MetasploitScanner)
    return s


class TestParseOutputNoEvidenceRegression(unittest.TestCase):

    def setUp(self):
        self.scanner = _scanner()

    def test_vulnerability_check_module_with_no_match_is_demoted_to_info(self):
        """Caso exacto observado: auxiliary/scanner/http/shellshock (default_sev='critical')
        corre limpio -- no debe reportarse como crítico."""
        output = "[*] Scanned 1 of 1 hosts (100% complete)\n[*] Auxiliary module execution completed"
        findings = self.scanner._parse_output(
            output, "auxiliary/scanner/http/shellshock", "dvwa", 80, default_sev="critical",
        )
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]['severity'], 'info', (
            "Un módulo de verificación de vulnerabilidad que no encontró evidencia "
            "NUNCA debe reportarse con la severidad 'si lo encontrara' (critical)."
        ))
        self.assertIn('sin evidencia', findings[0]['title'].lower())

    def test_ms15_034_against_non_windows_host_does_not_claim_critical(self):
        output = "[*] 172.21.0.8:80 - Scanned 1 of 1 hosts (100% complete)"
        findings = self.scanner._parse_output(
            output, "auxiliary/scanner/http/ms15_034_http_sys_memory_dump", "dvwa", 80, default_sev="critical",
        )
        self.assertEqual(findings[0]['severity'], 'info')
        self.assertEqual(findings[0]['cvss'], 0.0)

    def test_medium_severity_vuln_check_module_also_demoted(self):
        """MSF Options / MSF Dir Listing (default_sev='medium') -- mismo patrón."""
        output = "[*] Module completed"
        findings = self.scanner._parse_output(
            output, "auxiliary/scanner/http/options", "dvwa", 80, default_sev="medium",
        )
        self.assertEqual(findings[0]['severity'], 'info')

    def test_purely_informational_module_keeps_original_behavior(self):
        """http_version (default_sev='info') -- el banner SÍ es el dato útil, no se cambia."""
        output = "[*] 172.21.0.8:80 Apache/2.4.68 (Debian) ( Powered by PHP/8.5.11 )"
        findings = self.scanner._parse_output(
            output, "auxiliary/scanner/http/http_version", "dvwa", 80, default_sev="info",
        )
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]['severity'], 'info')
        self.assertIn('Apache', findings[0]['description'])

    def test_positive_match_still_reports_real_finding_at_its_own_severity(self):
        """Un patrón positivo real (ej. '[+] ...') SIGUE generando un hallazgo
        de verdad, sin tocar ese camino -- la corrección solo afecta el caso
        'no se encontró nada'."""
        output = "[+] 172.21.0.8:80 - VULNERABLE: Shellshock detected via User-Agent header"
        findings = self.scanner._parse_output(
            output, "auxiliary/scanner/http/shellshock", "dvwa", 80, default_sev="critical",
        )
        severities = {f['severity'] for f in findings}
        self.assertIn('critical', severities, "VULNERABLE: ... debe seguir reportándose como crítico.")

    def test_login_success_pattern_still_critical(self):
        output = "[+] 172.21.0.8:3306 - Login Successful: root:root"
        findings = self.scanner._parse_output(
            output, "auxiliary/scanner/mysql/mysql_login", "dvwa", 3306, default_sev="critical",
        )
        self.assertTrue(any(f['severity'] == 'critical' for f in findings))

    def test_demoted_finding_is_never_marked_simulated(self):
        """El hallazgo degradado sigue siendo un resultado REAL (el módulo sí corrió) --
        no debe confundirse con datos de modo demo."""
        findings = self.scanner._parse_output(
            "[*] done", "auxiliary/scanner/http/shellshock", "dvwa", 80, default_sev="critical",
        )
        self.assertFalse(findings[0]['simulated'])


if __name__ == '__main__':
    unittest.main()
