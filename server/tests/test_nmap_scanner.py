"""
Pruebas unitarias para server/modules/pentesting/nmap_scanner.py

Contexto (auditoría del módulo de Pentesting, ver AUDIT_PENTESTING.md):
Antes de esta ronda de correcciones, NmapScanner._simulate_scan() se
invocaba no solo cuando el binario de nmap no estaba instalado, sino
también cuando:
  - un escaneo real terminaba sin encontrar puertos abiertos (resultado
    negativo legítimo),
  - el host no resolvía por DNS,
  - el escaneo agotaba el timeout,
  - stdout venía vacío.
En todos esos casos se devolvían puertos "abiertos" FABRICADOS
(OpenSSH 8.9p1, Apache 2.4.52, MySQL 8.0.32, etc.) sin ninguna relación
con el objetivo real. Ese comportamiento viola el principio que el propio
proyecto ya aplica en ffuf.py/wappalyzer.py/patator.py ("_simulate_scan()
SOLO si la herramienta no está instalada") y es, en una herramienta de
pentesting, el peor tipo de falso positivo: un resultado NEGATIVO real
reemplazado por hallazgos POSITIVOS inventados.

Estas pruebas fijan el comportamiento corregido: la simulación solo debe
dispararse cuando el binario no está disponible (FileNotFoundError). Todo
otro desenlace (sin puertos, DNS roto, timeout, excepción de ejecución)
debe devolver un resultado real (lista vacía o un descriptor de error
explícito), nunca puertos inventados sin la marca 'simulated'.

Ejecutar (sin dependencias externas, solo stdlib):
    cd server && python3 -m unittest tests.test_nmap_scanner -v
"""

import subprocess
import sys
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))  # server/

from modules.pentesting.nmap_scanner import NmapScanner  # noqa: E402
from modules.pentesting.orchestrator import (             # noqa: E402
    SecurityOrchestrator, ScanTimeoutError,
)


NMAP_XML_TWO_OPEN_PORTS = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up"/>
    <port protocol="tcp" portid="22">
      <state state="open"/>
      <service name="ssh" product="OpenSSH" version="9.6" extrainfo="Ubuntu" cpe="cpe:/a:openbsd:openssh:9.6"/>
    </port>
    <port protocol="tcp" portid="80">
      <state state="open"/>
      <service name="http" product="nginx" version="1.24.0"/>
    </port>
    <port protocol="tcp" portid="8080">
      <state state="closed"/>
      <service name="http-proxy"/>
    </port>
  </host>
</nmaprun>"""

NMAP_XML_NO_OPEN_PORTS = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up"/>
    <port protocol="tcp" portid="22">
      <state state="filtered"/>
    </port>
  </host>
</nmaprun>"""

NMAP_XML_HOST_DOWN = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="down"/>
  </host>
</nmaprun>"""


def _completed(stdout='', stderr='', returncode=0):
    return subprocess.CompletedProcess(args=['nmap'], returncode=returncode, stdout=stdout, stderr=stderr)


class NmapScannerAvailableMixin:
    """Evita que _check_availability() dependa de que nmap exista en el PATH del sandbox."""

    def setUp(self):
        patcher = patch('modules.pentesting.nmap_scanner.shutil.which', return_value='/usr/bin/nmap')
        self.addCleanup(patcher.stop)
        patcher.start()
        self.scanner = NmapScanner(timeout=5)


class TestValidateTarget(NmapScannerAvailableMixin, unittest.TestCase):

    def test_valid_ip(self):
        ok, result = self.scanner._validate_target('192.168.1.10')
        self.assertTrue(ok)
        self.assertEqual(result, '192.168.1.10')

    def test_invalid_octet_rejected(self):
        ok, _ = self.scanner._validate_target('999.1.1.1')
        self.assertFalse(ok)

    def test_cidr_rejected(self):
        ok, reason = self.scanner._validate_target('10.0.0.0/24')
        self.assertFalse(ok)
        self.assertIn('CIDR', reason)

    def test_ip_range_rejected(self):
        ok, reason = self.scanner._validate_target('192.168.1.1-254')
        self.assertFalse(ok)
        self.assertIn('range', reason.lower())

    def test_hostname_with_hyphen_accepted(self):
        """Regression: un hostname de laboratorio como 'juice-shop' no debe
        confundirse con un rango IP solo por tener un guion."""
        ok, result = self.scanner._validate_target('juice-shop.local')
        self.assertTrue(ok)
        self.assertEqual(result, 'juice-shop.local')

    def test_url_target_extracts_hostname(self):
        ok, result = self.scanner._validate_target('http://example.com:8080/path')
        self.assertTrue(ok)
        self.assertEqual(result, 'example.com')

    def test_empty_target_rejected(self):
        ok, _ = self.scanner._validate_target('')
        self.assertFalse(ok)


class TestParseOutput(NmapScannerAvailableMixin, unittest.TestCase):

    def test_parses_open_ports_with_service_info(self):
        ports = self.scanner._parse_output(NMAP_XML_TWO_OPEN_PORTS)
        self.assertEqual(len(ports), 2)
        self.assertEqual(ports[0]['port'], 22)
        self.assertEqual(ports[0]['service'], 'ssh')
        self.assertEqual(ports[0]['product'], 'OpenSSH')
        self.assertNotIn('simulated', ports[0])

    def test_closed_ports_excluded(self):
        ports = self.scanner._parse_output(NMAP_XML_TWO_OPEN_PORTS)
        self.assertTrue(all(p['port'] != 8080 for p in ports))

    def test_host_down_yields_no_ports(self):
        ports = self.scanner._parse_output(NMAP_XML_HOST_DOWN)
        self.assertEqual(ports, [])

    def test_malformed_xml_returns_empty_list_not_exception(self):
        ports = self.scanner._parse_output('<not-even-xml')
        self.assertEqual(ports, [])


class TestScanFalsePositiveRegression(NmapScannerAvailableMixin, unittest.TestCase):
    """
    Núcleo de la corrección: un resultado NEGATIVO real (herramienta
    funcionó, no hay puertos abiertos) no debe convertirse en hallazgos
    POSITIVOS fabricados.
    """

    @patch('modules.pentesting.nmap_scanner.subprocess.run')
    def test_successful_scan_with_zero_open_ports_returns_empty_not_fake(self, mock_run):
        mock_run.return_value = _completed(stdout=NMAP_XML_NO_OPEN_PORTS, returncode=0)
        result = self.scanner.scan('scanme.example.com')
        self.assertEqual(result, [], (
            "Un escaneo real con 0 puertos abiertos debe devolver [] -- "
            "no debe rellenarse con puertos fabricados (ssh/http/mysql)."
        ))

    @patch('modules.pentesting.nmap_scanner.subprocess.run')
    def test_successful_scan_returns_real_parsed_ports_unmodified(self, mock_run):
        mock_run.return_value = _completed(stdout=NMAP_XML_TWO_OPEN_PORTS, returncode=0)
        result = self.scanner.scan('scanme.example.com')
        self.assertEqual(len(result), 2)
        for p in result:
            self.assertNotIn('simulated', p, "Un resultado real jamás debe llevar 'simulated'.")

    @patch('modules.pentesting.nmap_scanner.subprocess.run')
    def test_dns_failure_returns_empty_not_fake_ports(self, mock_run):
        mock_run.return_value = _completed(
            stdout='', stderr='Failed to resolve "noexiste.invalid". Name or service not known', returncode=1,
        )
        result = self.scanner.scan('noexiste.invalid')
        self.assertEqual(result, [])

    @patch('modules.pentesting.nmap_scanner.subprocess.run')
    def test_dns_failure_on_lab_named_host_does_not_leak_fake_juiceshop_ports(self, mock_run):
        """
        Regression específica: antes, _simulate_scan comprobaba 'juice' en el
        nombre del target ANTES de comprobar el escenario 'host_not_found',
        así que un host con DNS roto pero nombre tipo "juice-shop-caido"
        devolvía los puertos inventados de Juice Shop en vez de un
        resultado vacío/real.
        """
        mock_run.return_value = _completed(
            stdout='', stderr='Name or service not known', returncode=1,
        )
        result = self.scanner.scan('juice-shop-caido.local')
        self.assertEqual(result, [])

    @patch('modules.pentesting.nmap_scanner.subprocess.run')
    def test_empty_stdout_returns_empty_not_fake(self, mock_run):
        mock_run.return_value = _completed(stdout='', stderr='', returncode=0)
        result = self.scanner.scan('scanme.example.com')
        self.assertEqual(result, [])

    @patch('modules.pentesting.nmap_scanner.subprocess.run')
    def test_timeout_returns_explicit_error_descriptor_not_fake_ports(self, mock_run):
        mock_run.side_effect = subprocess.TimeoutExpired(cmd=['nmap'], timeout=5)
        result = self.scanner.scan('scanme.example.com')
        self.assertEqual(len(result), 1)
        self.assertIn('error', result[0])
        self.assertNotIn('product', result[0])  # no debe parecer un puerto real con servicio/producto inventado

    @patch('modules.pentesting.nmap_scanner.subprocess.run')
    def test_unexpected_exception_returns_error_descriptor_not_fake_ports(self, mock_run):
        mock_run.side_effect = PermissionError('denied')
        result = self.scanner.scan('scanme.example.com')
        self.assertEqual(len(result), 1)
        self.assertIn('error', result[0])


class TestScanSimulationOnlyWhenBinaryMissing(unittest.TestCase):
    """La simulación sigue existiendo, pero SOLO cuando nmap no está instalado."""

    def setUp(self):
        patcher = patch('modules.pentesting.nmap_scanner.shutil.which', return_value='/usr/bin/nmap')
        self.addCleanup(patcher.stop)
        patcher.start()
        self.scanner = NmapScanner(timeout=5)

    @patch('modules.pentesting.nmap_scanner.subprocess.run')
    def test_binary_missing_returns_clearly_flagged_simulated_data(self, mock_run):
        mock_run.side_effect = FileNotFoundError('nmap: not found')
        result = self.scanner.scan('dvwa.local')
        self.assertTrue(len(result) > 0)
        self.assertTrue(all(p.get('simulated') is True for p in result), (
            "Todo dato simulado debe llevar 'simulated': True explícito "
            "para que el frontend y los reportes lo marquen como tal."
        ))


class TestInvalidTargetShortCircuitsBeforeExec(NmapScannerAvailableMixin, unittest.TestCase):

    @patch('modules.pentesting.nmap_scanner.subprocess.run')
    def test_invalid_target_never_reaches_subprocess(self, mock_run):
        result = self.scanner.scan('10.0.0.0/24')
        self.assertEqual(result, [])
        mock_run.assert_not_called()


class TestOrchestratorRunNmapNeverFabricatesOnFailure(unittest.TestCase):
    """Regresión (auditoría pentesting, hallazgo documentado en §6.11,
    corregido 2026-11-07): orchestrator.run_nmap() devolvía, en
    timeout/excepción, [{'port': 'timeout', 'error': ...}] -- un item CON
    FORMA de puerto real (sin 'simulated'). scoring.py no lo excluía del
    score exportado (termina como hallazgo 'info' con nombre vacío) y
    cualquier consumidor que solo mirara `d.get('port')` sin filtrar
    'error' lo contaría como puerto real. Mismo criterio §2.1 ya aplicado
    en ffuf/gobuster/nuclei/zap/sqlmap/searchsploit/patator/
    injection_scanner/testssl: sin datos reales, lista vacía."""

    def setUp(self):
        self.orchestrator = SecurityOrchestrator()

    def test_timeout_returns_empty_list_not_fake_port(self):
        with patch.object(self.orchestrator.nmap, 'scan',
                           side_effect=ScanTimeoutError('nmap timeout')):
            result = self.orchestrator.run_nmap('http://dvwa:80')
        self.assertEqual(result, [])

    def test_generic_exception_returns_empty_list(self):
        with patch.object(self.orchestrator.nmap, 'scan',
                           side_effect=RuntimeError('boom')):
            result = self.orchestrator.run_nmap('http://dvwa:80')
        self.assertEqual(result, [])


if __name__ == '__main__':
    unittest.main()
