"""
Pruebas unitarias para:
  - server/modules/pentesting/zap_scanner.py::ZapScanner._get_alerts_paginated()
  - server/modules/pentesting/orchestrator.py::run_zap_full()

Contexto (auditoría de Pentesting, 2026-10-16, continuación de
§2.1/§6.5/§6.6/§6.7/gobuster/ffuf/patator/searchsploit):

Defecto 1 (el más grave encontrado en todo el módulo de Pentesting hasta
ahora): `ZapScanner._get_alerts_paginated()` -- el ÚLTIMO paso de
`scan()`, ejecutado DESPUÉS de que Spider + Ajax Spider + Active Scan ya
corrieron de verdad contra el target real -- envolvía CUALQUIER excepción
(incluida una sola página de alertas con JSON truncado, o un timeout
puntual de un solo request) en un `raise ZapScannerException(...)`. Esa
excepción se propagaba hasta el `except ZapScannerException` de scan(),
que descartaba TODO el trabajo real ya hecho (incluyendo las alertas
reales ya acumuladas en lotes anteriores) y devolvía
`_simulate_scan(target)`: 2-3 vulnerabilidades 100% inventadas (SQL
Injection crítica, XSS alta, etc., con 'simulated': True) para un escaneo
que sí corrió de verdad contra el objetivo real. Corregido para que
`_get_alerts_paginated()` devuelva las alertas reales ya acumuladas (o []
si no se alcanzó a leer ninguna) en vez de propagar el error hacia la
simulación -- nunca descarta trabajo real ya hecho.

Defecto 2 (mismo patrón que gobuster/ffuf/searchsploit, en la capa
orchestrator): `run_zap_full()` en sus `except ScanTimeoutError`/`except
Exception` devolvía `vulnerabilidades: [{'error': ..., 'risk': 'info' /
(nada), 'tool': 'zap'}]` -- un item sin 'severity' ni 'simulated'. Impacto
confirmado:
  1) app.py (paso Scoring) lo deja pasar el filtro `not v.get('simulated',
     False)` -- entra a calculate_security_score() como si fuera una
     vulnerabilidad real.
  2) scoring.py lee `vuln.get('severity', 'info')` -- como el item no
     trae 'severity' (usaba 'risk', que _transform_alert() no produce),
     cae en 'info' por defecto y suma una vulnerabilidad ficticia al
     breakdown/score, con nombre vacío.
  3) lib/scan-extractors.ts cuenta `s.vulnerabilities?.length` sin
     filtrar -- un timeout se contaba como "1 vulnerabilidad" en el panel.
Corregido para devolver `vulnerabilidades: []`, igual que los demás.

Ejecutar:
    cd server && python3 -m unittest tests.test_zap_scanner -v
"""

import sys
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))  # server/

from modules.pentesting.zap_scanner import ZapScanner  # noqa: E402
from modules.pentesting.orchestrator import (            # noqa: E402
    SecurityOrchestrator, ScanTimeoutError,
)


def _scanner():
    s = ZapScanner.__new__(ZapScanner)
    s.api_url = 'http://zap:8080'
    s.api_key = ''
    s.timeout = 600
    s.alert_batch_size = 100
    s.DEFAULT_PAGINATION_LIMIT = ZapScanner.DEFAULT_PAGINATION_LIMIT
    s._session = MagicMock()
    return s


def _resp(json_data, raise_for_status=None):
    r = MagicMock()
    r.json.return_value = json_data
    if raise_for_status:
        r.raise_for_status.side_effect = raise_for_status
    else:
        r.raise_for_status.return_value = None
    return r


class TestGetAlertsPaginatedNeverDiscardsRealDataOnError(unittest.TestCase):
    """Regresión del defecto principal: un error a mitad de la paginación
    debe devolver las alertas reales ya acumuladas (o []), nunca propagar
    una excepción que haga caer scan() en _simulate_scan()."""

    def setUp(self):
        self.scanner = _scanner()

    def test_error_after_one_real_batch_returns_that_batch_not_raises(self):
        real_alert = {
            'alertId': '1', 'name': 'Real SQL Injection', 'risk': 'High',
            'confidence': 'High', 'url': 'http://target/login',
        }
        responses = [
            _resp({'alerts': [real_alert]}),  # primer lote: 1 alerta real
        ]
        # Segunda llamada (start=100) lanza un error de red real.
        import requests
        responses.append(requests.exceptions.ConnectionError("boom"))

        def fake_get(*args, **kwargs):
            r = responses.pop(0)
            if isinstance(r, Exception):
                raise r
            return r

        self.scanner._session.get.side_effect = fake_get
        # batch_size=100 fuerza que haya una segunda iteración (1 < 100
        # ya habría cortado el loop, así que forzamos tamaño de lote 1 para
        # simular "lote lleno, pide la siguiente página").
        self.scanner.alert_batch_size = 1

        result = self.scanner._get_alerts_paginated('http://target')

        self.assertEqual(
            len(result), 1,
            "Debe conservar la alerta real ya recuperada antes del error, "
            "no descartarla.",
        )
        self.assertEqual(result[0]['name'], 'Real SQL Injection')
        self.assertNotIn('simulated', result[0])

    def test_error_on_first_request_returns_empty_list_not_raises(self):
        import requests
        self.scanner._session.get.side_effect = requests.exceptions.Timeout("timed out")
        result = self.scanner._get_alerts_paginated('http://target')
        self.assertEqual(result, [])

    def test_http_error_mid_pagination_does_not_raise(self):
        import requests
        self.scanner.alert_batch_size = 1
        real_alert = {'alertId': '1', 'name': 'Real XSS', 'risk': 'Medium'}
        responses = [_resp({'alerts': [real_alert]})]

        def fake_get(*args, **kwargs):
            if responses:
                return responses.pop(0)
            r = MagicMock()
            r.raise_for_status.side_effect = requests.exceptions.HTTPError("500")
            return r

        self.scanner._session.get.side_effect = fake_get
        try:
            result = self.scanner._get_alerts_paginated('http://target')
        except Exception as e:  # noqa: BLE001
            self.fail(f"_get_alerts_paginated() no debe propagar excepciones: {e}")
        self.assertEqual(len(result), 1)


class TestScanFallsBackToSimulationOnlyWhenZapTrulyUnreachable(unittest.TestCase):
    """scan() sigue usando _simulate_scan() para el caso legítimo (ZAP no
    responde en absoluto), pero ya no para un glitch en el último paso."""

    def test_zap_not_ready_uses_simulation(self):
        s = _scanner()
        with patch.object(s, '_wait_for_zap_ready', return_value=False):
            result = s.scan('http://target')
        self.assertTrue(len(result) >= 1)
        self.assertTrue(all(r.get('simulated') is True for r in result))

    def test_full_scan_with_late_pagination_error_returns_real_partial_alerts(self):
        """Caso central: spider + active scan reales corrieron, y el
        último paso (leer alertas) sufre un glitch -- NO debe terminar en
        datos simulados, sino en las alertas reales ya obtenidas."""
        s = _scanner()
        real_alert = {'alertId': '1', 'name': 'Real Finding', 'risk': 'High'}
        with patch.object(s, '_wait_for_zap_ready', return_value=True), \
             patch.object(s, 'access_target', return_value=True), \
             patch.object(s, '_start_spider', return_value='1'), \
             patch.object(s, '_wait_for_spider', return_value=True), \
             patch.object(s, '_run_ajax_spider', return_value=True), \
             patch.object(s, '_start_active_scan', return_value='1'), \
             patch.object(s, '_wait_for_active_scan', return_value=True):
            s._session.get.side_effect = [
                MagicMock(),  # newSession
            ]
            with patch.object(s, '_get_alerts_paginated', return_value=[
                s._transform_alert(real_alert)
            ]):
                result = s.scan('http://target')
        self.assertEqual(len(result), 1)
        self.assertFalse(result[0].get('simulated', False))
        self.assertEqual(result[0]['name'], 'Real Finding')


class TestOrchestratorRunZapFullNeverFabricatesVulnOnFailure(unittest.TestCase):
    """Regresión del defecto 2: timeout/error en run_zap_full() debe
    devolver vulnerabilidades: [], nunca un item sin 'simulated' que
    contamine el score y el conteo del panel de herramientas."""

    def setUp(self):
        self.orchestrator = SecurityOrchestrator()

    def test_timeout_returns_empty_vulnerabilities(self):
        with patch.object(self.orchestrator.zap, 'scan',
                           side_effect=ScanTimeoutError('zap timeout')):
            result = self.orchestrator.run_zap_full('http://example.test')
        self.assertEqual(result['vulnerabilidades'], [])
        self.assertEqual(result['urls_descubiertas'], [])
        self.assertFalse(result['success'])

    def test_generic_exception_returns_empty_vulnerabilities(self):
        with patch.object(self.orchestrator.zap, 'scan',
                           side_effect=RuntimeError('boom')):
            result = self.orchestrator.run_zap_full('http://example.test')
        self.assertEqual(result['vulnerabilidades'], [])
        self.assertFalse(result['success'])

    def test_successful_scan_passes_through_real_vulns(self):
        fake_vulns = [{'name': 'Real Finding', 'severity': 'high',
                       'url': 'http://example.test/login', 'simulated': False}]
        with patch.object(self.orchestrator.zap, 'scan', return_value=fake_vulns):
            result = self.orchestrator.run_zap_full('http://example.test')
        self.assertEqual(result['vulnerabilidades'], fake_vulns)
        self.assertTrue(result['success'])


if __name__ == '__main__':
    unittest.main()
