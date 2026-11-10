"""
Pruebas para server/remediation.py y server/remediation_store.py
(sección 8 y 10 de la auditoría de Pentesting: motor de recomendaciones y
seguimiento de remediación).

Ejecutar:
    cd server && python3 -m unittest tests.test_remediation -v
"""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))  # server/

from remediation import build_remediation, enrich_findings  # noqa: E402
from remediation_store import (  # noqa: E402
    RemediationStore, InvalidTransition, USER_SETTABLE_STATUSES, VERIFICATION_STATUSES,
)
import findings as findings_mod  # noqa: E402


def _finding(tool='sqlmap', title='Finding', injection_type='', cve='', evidence='', raw_extra=None):
    raw = {'tool': tool, 'injection_type': injection_type}
    if raw_extra:
        raw.update(raw_extra)
    return {
        'id': 'fp' + title[:8], 'tool': tool, 'family': 'web', 'title': title,
        'severity': 'high', 'target': 'http://lab.local/x', 'evidence': evidence,
        'cve': cve, 'raw': raw,
    }


class TestRemediationRuleMatching(unittest.TestCase):

    def test_sql_injection_by_injection_type(self):
        f = _finding(tool='sqlmap', title='SQL Injection: id', injection_type='sql_error_based')
        g = build_remediation(f)
        self.assertEqual(g['id'], 'sql-injection')
        self.assertEqual(g['confianza'], 'alta')
        self.assertTrue(g['pasos'])

    def test_xss_by_injection_scanner_type(self):
        f = _finding(tool='injection_scanner', title='XSS Reflejado', injection_type='xss_reflected')
        g = build_remediation(f)
        self.assertEqual(g['id'], 'xss')

    def test_command_injection(self):
        f = _finding(tool='injection_scanner', title='Command Injection', injection_type='command_injection')
        g = build_remediation(f)
        self.assertEqual(g['id'], 'command-injection')

    def test_ssrf(self):
        f = _finding(tool='injection_scanner', title='SSRF', injection_type='ssrf')
        self.assertEqual(build_remediation(f)['id'], 'ssrf')

    def test_known_cve_appends_nvd_reference(self):
        f = _finding(tool='nuclei', title='Apache Struts RCE', injection_type='', cve='CVE-2017-5638')
        g = build_remediation(f)
        self.assertEqual(g['id'], 'known-vulnerable-component')
        self.assertTrue(any('CVE-2017-5638' in r for r in g['referencias']))

    def test_unmatched_finding_falls_back_to_manual_review_without_inventing_details(self):
        f = _finding(tool='metasploit', title='Algo totalmente desconocido', evidence='detalle crudo')
        g = build_remediation(f)
        self.assertEqual(g['confianza'], 'requiere_revision_manual')
        self.assertIsNone(g['causa_probable'])
        self.assertIsNone(g['impacto'])
        self.assertEqual(g['pasos'], [])
        self.assertIn('detalle crudo', g['descripcion'])

    def test_enrich_findings_does_not_mutate_input(self):
        originals = [_finding(tool='sqlmap', title='SQL Injection: id', injection_type='sql_error_based')]
        enriched = enrich_findings(originals)
        self.assertNotIn('remediation', originals[0])
        self.assertIn('remediation', enriched[0])


class TestFindingsSqliResultsTypeFix(unittest.TestCase):
    """
    Regression: sqli_results contiene tanto resultados de SQLMap como de
    InjectionScanner (XSS/SSRF/XXE/etc.) -- antes, findings.py etiquetaba
    TODO lo que había ahí como tool='sqlmap' y title="SQL Injection: ...".
    """

    def test_sqlmap_result_keeps_sql_injection_title(self):
        scan = {'scan_type': 'web', 'sqli_results': [
            {'tool': 'sqlmap', 'url': 'http://x/a.php', 'parameter': 'id', 'severity': 'high'},
        ]}
        out = findings_mod.normalize_findings(scan)
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]['tool'], 'sqlmap')
        self.assertIn('SQL Injection', out[0]['title'])

    def test_injection_scanner_xss_result_is_not_mislabeled_as_sql_injection(self):
        scan = {'scan_type': 'web', 'sqli_results': [
            {'tool': 'injection_scanner', 'name': 'XSS Reflejado', 'injection_type': 'xss_reflected',
             'url': 'http://x/search', 'parameter': 'q', 'severity': 'high'},
        ]}
        out = findings_mod.normalize_findings(scan)
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]['tool'], 'injection_scanner')
        self.assertNotIn('SQL Injection', out[0]['title'])
        self.assertEqual(out[0]['title'], 'XSS Reflejado')

    def test_sqlmap_and_injection_scanner_results_on_same_param_are_not_merged_by_dedupe(self):
        """Antes, el fingerprint usaba tool='sqlmap' fijo para ambos -- un XSS y
        una inyección SQL sobre el mismo parámetro podían fusionarse en uno."""
        scan = {'scan_type': 'web', 'sqli_results': [
            {'tool': 'sqlmap', 'url': 'http://x/a.php', 'parameter': 'id', 'severity': 'high'},
            {'tool': 'injection_scanner', 'name': 'XSS Reflejado', 'injection_type': 'xss_reflected',
             'url': 'http://x/a.php', 'parameter': 'id', 'severity': 'high'},
        ]}
        out = findings_mod.normalize_findings(scan)
        ids = {f['id'] for f in out}
        self.assertEqual(len(ids), 2, "Deben seguir siendo dos hallazgos distintos (ids de fingerprint distintos).")


class TestRemediationStoreStateMachine(unittest.TestCase):

    def setUp(self):
        self.store = RemediationStore(redis_client=None)

    def test_default_status_is_pending(self):
        record = self.store.get('nuevo-hallazgo')
        self.assertEqual(record['status'], 'pending')
        self.assertEqual(record['history'], [])

    def test_user_can_declare_in_remediation(self):
        record = self.store.set_status('f1', 'in_remediation', comment='trabajando')
        self.assertEqual(record['status'], 'in_remediation')
        self.assertEqual(len(record['history']), 1)
        self.assertEqual(record['history'][0]['type'], 'user_declaration')

    def test_user_cannot_declare_verified_directly(self):
        with self.assertRaises(InvalidTransition):
            self.store.set_status('f1', 'verified')

    def test_user_cannot_declare_reopened_directly(self):
        with self.assertRaises(InvalidTransition):
            self.store.set_status('f1', 'reopened')

    def test_user_settable_statuses_are_exactly_the_three_non_verification_ones(self):
        self.assertEqual(set(USER_SETTABLE_STATUSES), {'pending', 'in_remediation', 'fixed_pending_verification'})
        self.assertEqual(set(VERIFICATION_STATUSES), {'verified', 'reopened'})

    def test_verification_confirming_fix_sets_verified(self):
        self.store.set_status('f1', 'fixed_pending_verification', comment='aplicado el fix')
        record = self.store.record_verification('f1', persists=False, evidence={'retest': 'header presente'})
        self.assertEqual(record['status'], 'verified')
        self.assertEqual(record['history'][-1]['type'], 'verification')

    def test_verification_finding_issue_persists_sets_reopened(self):
        self.store.set_status('f1', 'fixed_pending_verification')
        record = self.store.record_verification('f1', persists=True, evidence={'retest': 'sigue vulnerable'})
        self.assertEqual(record['status'], 'reopened')

    def test_inconclusive_verification_does_not_change_status(self):
        """Criterio de aceptación: una prueba fallida/incompleta NO marca como corregido."""
        self.store.set_status('f1', 'fixed_pending_verification')
        before = self.store.get('f1')['status']
        record = self.store.record_inconclusive_verification('f1', reason='herramienta no disponible en el entorno')
        self.assertEqual(record['status'], before)
        self.assertEqual(record['history'][-1]['type'], 'verification_inconclusive')

    def test_recurrence_reopens_a_previously_verified_finding(self):
        self.store.set_status('f1', 'fixed_pending_verification')
        self.store.record_verification('f1', persists=False, evidence={})
        self.assertEqual(self.store.get('f1')['status'], 'verified')
        record = self.store.reopen_from_recurrence('f1', scan_id='scan-123')
        self.assertEqual(record['status'], 'reopened')

    def test_recurrence_on_non_verified_finding_is_a_noop(self):
        self.store.set_status('f1', 'pending')
        record = self.store.reopen_from_recurrence('f1', scan_id='scan-123')
        self.assertEqual(record['status'], 'pending')

    def test_history_is_cumulative_across_transitions(self):
        self.store.set_status('f1', 'in_remediation')
        self.store.set_status('f1', 'fixed_pending_verification')
        self.store.record_verification('f1', persists=False, evidence={})
        record = self.store.get('f1')
        self.assertEqual(len(record['history']), 3)


class _FakeRedisDown:
    """Simula Redis caído -- toda operación lanza, el store debe degradar a memoria."""
    def get(self, *a, **k): raise ConnectionError('redis down')
    def setex(self, *a, **k): raise ConnectionError('redis down')


class TestRemediationStoreFailOpen(unittest.TestCase):
    """Mismo criterio fail-open que modules/common/circuit_breaker.py."""

    def test_falls_back_to_memory_when_redis_unavailable(self):
        store = RemediationStore(redis_client=_FakeRedisDown())
        record = store.set_status('f1', 'in_remediation', comment='x')
        self.assertEqual(record['status'], 'in_remediation')
        self.assertEqual(store.get('f1')['status'], 'in_remediation')


if __name__ == '__main__':
    unittest.main()
