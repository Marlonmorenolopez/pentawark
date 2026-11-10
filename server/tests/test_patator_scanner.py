"""
Pruebas unitarias para server/modules/pentesting/patator.py

Contexto (auditoría de Pentesting, 2026-10-16, continuación de
§2.1/§6.5/§6.6/§6.7/gobuster/ffuf):

Defecto 1 (falso positivo de credencial, confirmado por lectura +
reproducción): `_analyze_results()` aceptaba como "candidato" (luego
reportado aguas abajo como 'Credenciales débiles encontradas',
'success': True, severidad 'high') cualquier intento con
`status == 200 and size_diff > 100` -- INCLUSO con score=0, es decir, SIN
redirect (301/302/303), SIN texto de éxito, y sin que el criterio de
desviación de tamaño con baseline consistente se cumpliera. Un formulario
de login que simplemente eco-ea el username enviado en su página de error
(tamaño de respuesta variable por intento, sin ningún patrón de
fail_patterns) activaba esta rama para casi cualquier combinación
usuario/contraseña probada, sin evidencia real de autenticación exitosa.

Defecto 2 (mismo patrón que §2.1 Nmap/Wappalyzer/Nuclei): un error de
conexión real contra el objetivo (DNS roto, conexión rechazada, timeout)
en `_brute_force_with_requests()` devolvía `None` -- indistinguible de
"la librería requests no está instalada" -- y `scan()` interpreta `None`
como "seguir con el siguiente método", cayendo en
`_brute_force_with_binary()` (si el binario está disponible) o, si
tampoco lo está (el caso real observado: "Patator not found in PATH"),
en `_simulate_scan()`, que fabrica una credencial fija
('admin'/'password', 'simulated': True) sin relación alguna con el
objetivo. Corregido para que un error de conexión/timeout real devuelva
`[]` directamente (scan() lo trata como resultado final, sin pasar a
simulación).

Ejecutar:
    cd server && python3 -m unittest tests.test_patator_scanner -v
"""

import sys
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))  # server/

from modules.pentesting.patator import PatatorScanner  # noqa: E402


def _scanner(available=False):
    s = PatatorScanner.__new__(PatatorScanner)
    s.timeout = 120
    s.threads = 4
    s.command = 'patator'
    s._available = available
    return s


def _attempt(status=200, size=1000, text='', username='u', password='p'):
    return {
        'username': username, 'password': password, 'status': status,
        'size': size, 'url': 'http://example.test/login', 'text': text,
        'session_cookie': '',
    }


class TestAnalyzeResultsNeverAcceptsZeroScoreCandidate(unittest.TestCase):
    """Regresión del defecto principal: una respuesta 200 simplemente más
    grande que el baseline, sin ninguna otra señal, NUNCA debe convertirse
    en un candidato de credencial encontrada."""

    def setUp(self):
        self.scanner = _scanner()

    def test_size_only_deviation_without_consistent_baseline_is_rejected(self):
        # baseline_freq baja (tamaños muy dispersos) -> el bonus de +30 por
        # desviación de tamaño NO se activa (requiere baseline_freq >= 0.7).
        # Antes del fix, igual calificaba vía el fallback de score=0.
        attempts = [
            _attempt(status=200, size=1000 + i * 150, text='please try again')
            for i in range(10)
        ]
        result = self.scanner._analyze_results(attempts)
        self.assertEqual(
            result, [],
            "Una respuesta 200 que solo varía de tamaño (sin redirect, sin "
            "texto de éxito, sin baseline consistente) no es evidencia de "
            "credencial válida.",
        )

    def test_redirect_alone_is_accepted(self):
        attempts = [_attempt(status=200, size=1000) for _ in range(9)]
        attempts.append(_attempt(status=302, size=50, username='admin', password='password'))
        result = self.scanner._analyze_results(attempts)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]['username'], 'admin')

    def test_success_text_alone_is_accepted(self):
        attempts = [_attempt(status=200, size=1000) for _ in range(9)]
        attempts.append(_attempt(status=200, size=1000, text='welcome to your dashboard',
                                  username='admin', password='password'))
        result = self.scanner._analyze_results(attempts)
        self.assertEqual(len(result), 1)

    def test_size_deviation_with_consistent_baseline_is_still_accepted(self):
        # baseline_freq alta (9/10 iguales) + desviación > 50 -> sí califica.
        attempts = [_attempt(status=200, size=1000) for _ in range(9)]
        attempts.append(_attempt(status=200, size=1200, username='admin', password='password'))
        result = self.scanner._analyze_results(attempts)
        self.assertEqual(len(result), 1)

    def test_fail_pattern_in_text_is_always_rejected_even_with_redirect(self):
        attempts = [_attempt(status=302, size=50, text='invalid credentials, try again')]
        result = self.scanner._analyze_results(attempts)
        self.assertEqual(result, [])

    def test_empty_attempts_returns_empty_list(self):
        self.assertEqual(self.scanner._analyze_results([]), [])


class TestBruteForceWithRequestsNeverFallsBackToSimulationOnConnectionError(unittest.TestCase):
    """Regresión del defecto 2: un objetivo inalcanzable debe devolver []
    directamente, nunca None (que cascadea a _simulate_scan())."""

    def setUp(self):
        self.scanner = _scanner(available=False)

    def test_connection_error_returns_empty_list_not_none(self):
        import requests
        with patch('requests.Session') as mock_session_cls:
            mock_session = MagicMock()
            mock_session.get.side_effect = requests.exceptions.ConnectionError("refused")
            mock_session_cls.return_value = mock_session
            result = self.scanner._brute_force_with_requests(
                'http://unreachable.test/login', 'username', 'password',
                'Login failed', ['admin'], ['password'],
            )
        self.assertEqual(
            result, [],
            "Un error de conexión real NUNCA debe devolver None (que haría "
            "que scan() caiga en _simulate_scan() y fabrique una credencial "
            "falsa admin/password).",
        )

    def test_timeout_returns_empty_list_not_none(self):
        import requests
        with patch('requests.Session') as mock_session_cls:
            mock_session = MagicMock()
            mock_session.get.side_effect = requests.exceptions.Timeout("timed out")
            mock_session_cls.return_value = mock_session
            result = self.scanner._brute_force_with_requests(
                'http://slow.test/login', 'username', 'password',
                'Login failed', ['admin'], ['password'],
            )
        self.assertEqual(result, [])

    def test_scan_with_unreachable_target_never_returns_simulated_data(self):
        """Prueba de extremo a extremo vía scan(): objetivo inalcanzable +
        binario no disponible NUNCA debe terminar en datos simulados."""
        import requests
        with patch('requests.Session') as mock_session_cls:
            mock_session = MagicMock()
            mock_session.get.side_effect = requests.exceptions.ConnectionError("refused")
            mock_session_cls.return_value = mock_session
            result = self.scanner.scan('http://unreachable.test')
        self.assertEqual(result, [])
        self.assertFalse(
            any(r.get('simulated') for r in result),
            "Un objetivo inalcanzable no debe producir hallazgos simulados.",
        )


class TestDetectFormFieldsAndParseOutput(unittest.TestCase):
    """Sanity checks de las utilidades de parsing — no relacionadas con
    los defectos de arriba, pero cubiertas por primera vez en esta
    auditoría."""

    def setUp(self):
        self.scanner = _scanner()

    def test_detects_standard_login_form_fields(self):
        html = (
            '<input type="text" name="username">'
            '<input type="password" name="password">'
            '<input type="hidden" name="user_token" value="abc123">'
        )
        fields = self.scanner._detect_form_fields(html)
        self.assertEqual(fields.get('pass_field'), 'password')
        self.assertEqual(fields.get('user_field'), 'username')
        self.assertEqual(fields.get('extra_fields', {}).get('user_token'), 'abc123')

    def test_parse_output_extracts_credentials_from_patator_binary_line(self):
        output = "20:30:00 PAYLOAD:admin:password 200 size:1234"
        result = self.scanner._parse_output(output)
        self.assertEqual(result, [{'username': 'admin', 'password': 'password'}])

    def test_parse_output_ignores_failed_attempts(self):
        output = "20:30:00 PAYLOAD:admin:wrong 401 size:100"
        result = self.scanner._parse_output(output)
        self.assertEqual(result, [])


if __name__ == '__main__':
    unittest.main()
