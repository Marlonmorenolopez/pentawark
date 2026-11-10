"""
Pruebas unitarias para la integración de jwt_tool en Pentesting:
  - server/modules/pentesting/jwt_tool_scanner.py (JWTToolScanner)
  - server/modules/pentesting/orchestrator.py::run_jwt_tool()
  - server/skill_execution_registry.py (entrada 'jwt-tool')

Contexto (Fase 2 del plan de la "Auditoría de cobertura de vulnerabilidades
— PentaWark", 2026-11, autorizada explícitamente por el usuario): ver el
docstring de jwt_tool_scanner.py para la decisión de implementar el
análisis en Python puro (decode + verificación HMAC real) en vez de
invocar el binario externo jwt_tool.py por subprocess. Estas pruebas no
mockean nada externo porque el módulo no depende de ningún binario ni red
-- son pruebas reales de principio a fin (decodificación base64url real,
firma HMAC real con la librería estándar).

Ejecutar:
    cd server && python3 -m unittest tests.test_jwt_tool_scanner -v
"""

import base64
import hashlib
import hmac
import json
import sys
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))  # server/

from modules.pentesting.jwt_tool_scanner import JWTToolScanner  # noqa: E402


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('ascii')


def _make_jwt(header: dict, payload: dict, secret: str = None, alg: str = 'HS256', signature: bytes = None) -> str:
    header_b64 = _b64url(json.dumps(header).encode('utf-8'))
    payload_b64 = _b64url(json.dumps(payload).encode('utf-8'))
    signing_input = f"{header_b64}.{payload_b64}".encode('ascii')
    if signature is not None:
        sig = signature
    elif secret is not None and alg.upper() in ('HS256', 'HS384', 'HS512'):
        digestmod = {'HS256': hashlib.sha256, 'HS384': hashlib.sha384, 'HS512': hashlib.sha512}[alg.upper()]
        sig = hmac.new(secret.encode('utf-8'), signing_input, digestmod).digest()
    else:
        sig = b''
    return f"{header_b64}.{payload_b64}.{_b64url(sig) if sig else ''}"


class TestInvalidTokenFormat(unittest.TestCase):

    def test_wrong_number_of_segments_reports_info_not_crash(self):
        scanner = JWTToolScanner()
        result = scanner.scan('not.a.valid.jwt.token')
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]['severity'], 'info')
        self.assertFalse(result[0]['simulated'])

    def test_empty_string_reports_info_not_crash(self):
        scanner = JWTToolScanner()
        result = scanner.scan('')
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]['severity'], 'info')

    def test_bearer_prefix_is_stripped(self):
        scanner = JWTToolScanner()
        token = _make_jwt({'alg': 'HS256', 'typ': 'JWT'}, {'sub': 'admin', 'exp': 9999999999}, secret='secret')
        result = scanner.scan(f"Bearer {token}")
        # Debe analizarse igual que sin el prefijo -- debe encontrar el
        # secreto débil 'secret', no fallar por formato.
        self.assertTrue(any(f.get('secret') == 'secret' for f in result))

    def test_unparseable_header_reports_info(self):
        scanner = JWTToolScanner()
        bogus_header = _b64url(b'not-json-at-all')
        payload_b64 = _b64url(json.dumps({'sub': 'x'}).encode())
        token = f"{bogus_header}.{payload_b64}.sig"
        result = scanner.scan(token)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]['severity'], 'info')


class TestAlgNoneDetection(unittest.TestCase):

    def test_alg_none_is_reported_as_critical(self):
        scanner = JWTToolScanner()
        token = _make_jwt({'alg': 'none', 'typ': 'JWT'}, {'sub': 'admin'}, signature=b'')
        result = scanner.scan(token)
        self.assertTrue(any(f['severity'] == 'critical' and 'none' in f['name'].lower() for f in result))

    def test_alg_none_case_insensitive(self):
        scanner = JWTToolScanner()
        token = _make_jwt({'alg': 'None', 'typ': 'JWT'}, {'sub': 'admin'}, signature=b'')
        result = scanner.scan(token)
        self.assertTrue(any(f['severity'] == 'critical' for f in result))


class TestWeakSecretCracking(unittest.TestCase):

    def test_hs256_with_known_weak_secret_is_cracked_and_reported_in_plain_text(self):
        scanner = JWTToolScanner()
        token = _make_jwt(
            {'alg': 'HS256', 'typ': 'JWT'},
            {'sub': 'admin', 'exp': 9999999999},
            secret='admin',
        )
        result = scanner.scan(token)
        cracked = [f for f in result if f.get('secret') is not None]
        self.assertEqual(len(cracked), 1)
        self.assertEqual(cracked[0]['secret'], 'admin')
        self.assertEqual(cracked[0]['severity'], 'critical')
        self.assertFalse(cracked[0]['simulated'])

    def test_hs256_with_strong_unknown_secret_is_not_fabricated_as_finding(self):
        """Regresión del patrón §2.1: si el secreto NO está en la lista
        corta, no se debe inventar un hallazgo de 'secreto débil' -- la
        ausencia de evidencia no es evidencia de ausencia, pero tampoco se
        fabrica un hallazgo positivo falso."""
        scanner = JWTToolScanner()
        token = _make_jwt(
            {'alg': 'HS256', 'typ': 'JWT'},
            {'sub': 'admin', 'exp': 9999999999},
            secret='Xk9#mP2$vL7!qR4&wZ8@',
        )
        result = scanner.scan(token)
        self.assertFalse(any(f.get('secret') is not None for f in result))

    def test_hs256_missing_signature_is_flagged(self):
        scanner = JWTToolScanner()
        token = _make_jwt({'alg': 'HS256', 'typ': 'JWT'}, {'sub': 'admin', 'exp': 9999999999}, signature=b'')
        result = scanner.scan(token)
        self.assertTrue(any('sin firma' in f['name'].lower() for f in result))


class TestClaimsAndHeaderChecks(unittest.TestCase):

    def test_missing_exp_claim_is_flagged_medium(self):
        scanner = JWTToolScanner()
        token = _make_jwt({'alg': 'HS256', 'typ': 'JWT'}, {'sub': 'admin'}, secret='Xk9#mP2$vL7!qR4&wZ8@')
        result = scanner.scan(token)
        self.assertTrue(any(f['severity'] == 'medium' and 'exp' in f['name'] for f in result))

    def test_present_exp_claim_is_not_flagged(self):
        scanner = JWTToolScanner()
        token = _make_jwt({'alg': 'HS256', 'typ': 'JWT'}, {'sub': 'admin', 'exp': 9999999999}, secret='Xk9#mP2$vL7!qR4&wZ8@')
        result = scanner.scan(token)
        self.assertFalse(any('exp' in f['name'] for f in result))

    def test_suspicious_kid_header_is_flagged_high(self):
        scanner = JWTToolScanner()
        token = _make_jwt(
            {'alg': 'HS256', 'typ': 'JWT', 'kid': '../../../../etc/passwd'},
            {'sub': 'admin', 'exp': 9999999999},
            secret='Xk9#mP2$vL7!qR4&wZ8@',
        )
        result = scanner.scan(token)
        self.assertTrue(any(f['severity'] == 'high' and 'kid' in f['name'].lower() for f in result))

    def test_benign_kid_header_is_not_flagged(self):
        scanner = JWTToolScanner()
        token = _make_jwt(
            {'alg': 'HS256', 'typ': 'JWT', 'kid': 'key-2026-01'},
            {'sub': 'admin', 'exp': 9999999999},
            secret='Xk9#mP2$vL7!qR4&wZ8@',
        )
        result = scanner.scan(token)
        self.assertFalse(any('kid' in f['name'].lower() for f in result))

    def test_jku_header_present_is_flagged_for_manual_review(self):
        scanner = JWTToolScanner()
        token = _make_jwt(
            {'alg': 'HS256', 'typ': 'JWT', 'jku': 'https://attacker.example/keys.json'},
            {'sub': 'admin', 'exp': 9999999999},
            secret='Xk9#mP2$vL7!qR4&wZ8@',
        )
        result = scanner.scan(token)
        self.assertTrue(any('jku' in f['name'].lower() for f in result))


class TestOrchestratorRunJwtTool(unittest.TestCase):

    def test_run_jwt_tool_delegates_to_scanner_and_returns_its_result(self):
        import modules.pentesting.orchestrator as orch_mod

        orchestrator = orch_mod.SecurityOrchestrator.__new__(orch_mod.SecurityOrchestrator)
        orchestrator.TIMEOUTS = orch_mod.SecurityOrchestrator.TIMEOUTS
        orchestrator.jwt_tool = MagicMock()
        orchestrator.jwt_tool.scan.return_value = [
            {'name': "JWT con alg='none'", 'severity': 'critical', 'tool': 'jwt_tool', 'simulated': False},
        ]
        result = orchestrator.run_jwt_tool('a.b.c')
        orchestrator.jwt_tool.scan.assert_called_once_with('a.b.c')
        self.assertEqual(result[0]['severity'], 'critical')

    def test_run_jwt_tool_timeout_returns_empty_list_not_sentinel(self):
        import modules.pentesting.orchestrator as orch_mod

        orchestrator = orch_mod.SecurityOrchestrator.__new__(orch_mod.SecurityOrchestrator)
        orchestrator.TIMEOUTS = orch_mod.SecurityOrchestrator.TIMEOUTS
        orchestrator.jwt_tool = MagicMock()

        def _hangs(token):
            raise orch_mod.ScanTimeoutError()

        orchestrator.jwt_tool.scan.side_effect = _hangs
        with patch.object(orch_mod, 'run_with_timeout', side_effect=lambda func, args=(), kwargs=None, seconds=0, default=None: default):
            result = orchestrator.run_jwt_tool('a.b.c')
        self.assertEqual(result, [])


class TestSkillRegistryEntry(unittest.TestCase):

    def test_jwt_tool_registered_with_jwt_token_subject_and_token_kwarg(self):
        import skill_execution_registry as reg

        entry = reg.get_runner_entry('jwt-tool')
        self.assertIsNotNone(entry)
        self.assertEqual(entry.runner_attr, 'run_jwt_tool')
        self.assertEqual(entry.status, 'available')
        self.assertEqual(entry.schema.subject_kind, 'jwt_token')
        self.assertEqual(entry.schema.subject_kwarg, 'token')
        self.assertEqual(entry.schema.fields, [])


if __name__ == '__main__':
    unittest.main()
