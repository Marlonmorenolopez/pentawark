"""
Pruebas unitarias para server/modules/pentesting/interactsh_client.py
(InteractshSession) -- Fase 3 (2026-11, OAST, autorizada por el usuario).

LIMITACIÓN HONESTA (igual que en el docstring del propio módulo): este
entorno de sandbox no tiene conectividad de red hacia ningún servidor de
Interactsh real, así que estas pruebas NO validan el protocolo de red
real contra un servidor en vivo. Lo que sí validan:

  1. El round-trip criptográfico propio (RSA-OAEP + AES-CFB): se cifra
     una interacción falsa EXACTAMENTE como el propio código de
     `InteractshSession` espera recibirla de /poll (usando la llave
     pública que el propio código generó), y se confirma que
     `_decrypt_aes_key`/`_decrypt_entry` la recuperan sin bugs de
     implementación. Esto prueba que el cifrado/descifrado está bien
     escrito -- NO prueba que coincida con el formato exacto que el
     servidor real de Interactsh usa (eso solo se puede confirmar con la
     verificación manual puntual descrita en AUDIT_PENTESTING.md §6.13).
  2. El manejo defensivo de errores de red/formato en register()/poll()/
     deregister(): ningún camino de fallo debe lanzar una excepción ni
     fabricar una sesión/interacción falsa -- siempre `None`/`[]`.

Ejecutar:
    cd server && python3 -m unittest tests.test_interactsh_client -v
"""

import base64
import json
import sys
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock

import requests

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))  # server/

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from modules.pentesting.interactsh_client import (  # noqa: E402
    InteractshSession, DEFAULT_SERVER,
)


def _fake_server_poll_response(session: InteractshSession, interactions: list) -> dict:
    """Construye un dict como el que /poll devolvería, cifrando
    `interactions` con la llave PÚBLICA de `session` (que ya debe estar
    registrada) -- exactamente como el servidor real está documentado
    que lo hace. Usado solo para probar el round-trip de descifrado del
    propio cliente, no el protocolo de red en sí."""
    aes_key = b'0123456789abcdef'  # 16 bytes -- AES-128
    public_key = session._private_key.public_key()
    encrypted_aes_key = public_key.encrypt(
        aes_key,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(), label=None),
    )
    entries_b64 = []
    for interaction in interactions:
        iv = b'\x00' * 16
        encryptor = Cipher(algorithms.AES(aes_key), modes.CFB(iv)).encryptor()
        ciphertext = encryptor.update(json.dumps(interaction).encode('utf-8')) + encryptor.finalize()
        entries_b64.append(base64.b64encode(iv + ciphertext).decode('ascii'))
    return {
        'data': entries_b64,
        'aes_key': base64.b64encode(encrypted_aes_key).decode('ascii'),
    }


class TestRegister(unittest.TestCase):

    def test_register_success_sets_canary_domain(self):
        session = InteractshSession()
        with patch('modules.pentesting.interactsh_client.requests.post') as mock_post:
            mock_post.return_value = MagicMock(status_code=200)
            canary = session.register()
        self.assertIsNotNone(canary)
        self.assertTrue(session.registered)
        self.assertTrue(canary.endswith(f".{DEFAULT_SERVER}"))
        self.assertEqual(canary, session.canary_domain)

    def test_register_sends_expected_payload_shape(self):
        session = InteractshSession()
        with patch('modules.pentesting.interactsh_client.requests.post') as mock_post:
            mock_post.return_value = MagicMock(status_code=200)
            session.register()
        _, kwargs = mock_post.call_args
        body = kwargs['json']
        self.assertIn('public-key', body)
        self.assertIn('secret-key', body)
        self.assertIn('correlation-id', body)
        # La llave pública viaja en PEM base64, no en crudo.
        decoded = base64.b64decode(body['public-key'])
        self.assertIn(b'PUBLIC KEY', decoded)

    def test_register_returns_none_on_non_200(self):
        session = InteractshSession()
        with patch('modules.pentesting.interactsh_client.requests.post') as mock_post:
            mock_post.return_value = MagicMock(status_code=500)
            canary = session.register()
        self.assertIsNone(canary)
        self.assertFalse(session.registered)

    def test_register_returns_none_on_network_error(self):
        session = InteractshSession()
        with patch('modules.pentesting.interactsh_client.requests.post',
                   side_effect=requests.exceptions.ConnectionError("no route to host")):
            canary = session.register()
        self.assertIsNone(canary)
        self.assertFalse(session.registered)

    def test_register_returns_none_on_unexpected_error_never_raises(self):
        """Si incluso la generación de la llave RSA fallara, register()
        debe devolver None, nunca propagar la excepción -- la sesión OAST
        es opcional y un fallo aquí no debe tumbar el resto del scan."""
        session = InteractshSession()
        with patch('modules.pentesting.interactsh_client.rsa.generate_private_key',
                   side_effect=RuntimeError("boom")):
            canary = session.register()
        self.assertIsNone(canary)
        self.assertFalse(session.registered)

    def test_canary_domain_is_none_before_register(self):
        session = InteractshSession()
        self.assertIsNone(session.canary_domain)


class TestPoll(unittest.TestCase):

    def _registered_session(self):
        session = InteractshSession()
        with patch('modules.pentesting.interactsh_client.requests.post') as mock_post:
            mock_post.return_value = MagicMock(status_code=200)
            session.register()
        return session

    def test_poll_without_registration_returns_empty_list(self):
        session = InteractshSession()
        self.assertEqual(session.poll(), [])

    def test_poll_decrypts_real_round_trip_correctly(self):
        """Valida el round-trip criptográfico propio (ver nota del
        módulo arriba) -- NO el protocolo de red real."""
        session = self._registered_session()
        fake_interaction = {
            'protocol': 'dns',
            'full-id': 'deadbeefcafe12.abc123.oast.pro',
            'remote-address': '203.0.113.5',
            'timestamp': '2026-11-08T10:00:00Z',
        }
        fake_response_body = _fake_server_poll_response(session, [fake_interaction])
        with patch('modules.pentesting.interactsh_client.requests.get') as mock_get:
            mock_get.return_value = MagicMock(status_code=200, json=lambda: fake_response_body)
            interactions = session.poll()
        self.assertEqual(len(interactions), 1)
        self.assertEqual(interactions[0]['full-id'], 'deadbeefcafe12.abc123.oast.pro')
        self.assertEqual(interactions[0]['protocol'], 'dns')

    def test_poll_sends_correlation_id_and_secret(self):
        session = self._registered_session()
        with patch('modules.pentesting.interactsh_client.requests.get') as mock_get:
            mock_get.return_value = MagicMock(status_code=200, json=lambda: {'data': []})
            session.poll()
        _, kwargs = mock_get.call_args
        self.assertEqual(kwargs['params']['id'], session.correlation_id)
        self.assertEqual(kwargs['params']['secret'], session.secret_key)

    def test_poll_returns_empty_on_non_200(self):
        session = self._registered_session()
        with patch('modules.pentesting.interactsh_client.requests.get') as mock_get:
            mock_get.return_value = MagicMock(status_code=503)
            self.assertEqual(session.poll(), [])

    def test_poll_returns_empty_on_network_error(self):
        session = self._registered_session()
        with patch('modules.pentesting.interactsh_client.requests.get',
                   side_effect=requests.exceptions.Timeout("timed out")):
            self.assertEqual(session.poll(), [])

    def test_poll_returns_empty_on_invalid_json(self):
        session = self._registered_session()
        with patch('modules.pentesting.interactsh_client.requests.get') as mock_get:
            resp = MagicMock(status_code=200)
            resp.json.side_effect = ValueError("not json")
            mock_get.return_value = resp
            self.assertEqual(session.poll(), [])

    def test_poll_returns_empty_when_no_data_entries(self):
        session = self._registered_session()
        with patch('modules.pentesting.interactsh_client.requests.get') as mock_get:
            mock_get.return_value = MagicMock(status_code=200, json=lambda: {'data': []})
            self.assertEqual(session.poll(), [])

    def test_poll_returns_empty_when_aes_key_missing(self):
        session = self._registered_session()
        with patch('modules.pentesting.interactsh_client.requests.get') as mock_get:
            mock_get.return_value = MagicMock(
                status_code=200, json=lambda: {'data': ['Zm9v'], 'aes_key': None})
            self.assertEqual(session.poll(), [])

    def test_poll_returns_empty_when_aes_key_undecryptable(self):
        """aes_key corrupto/no cifrado con esta llave -- debe descartarse
        sin lanzar, nunca fabricar interacciones a partir de basura."""
        session = self._registered_session()
        garbage_aes_key = base64.b64encode(b'not a valid rsa ciphertext').decode('ascii')
        with patch('modules.pentesting.interactsh_client.requests.get') as mock_get:
            mock_get.return_value = MagicMock(
                status_code=200,
                json=lambda: {'data': ['Zm9v'], 'aes_key': garbage_aes_key})
            self.assertEqual(session.poll(), [])

    def test_poll_skips_single_corrupt_entry_but_keeps_valid_ones(self):
        session = self._registered_session()
        good_interaction = {'protocol': 'http', 'full-id': 'aaaa.c.oast.pro'}
        fake_body = _fake_server_poll_response(session, [good_interaction])
        # Insertar una entrada corrupta junto a la válida.
        fake_body['data'].append(base64.b64encode(b'garbage-not-16-bytes-iv-ok').decode('ascii'))
        with patch('modules.pentesting.interactsh_client.requests.get') as mock_get:
            mock_get.return_value = MagicMock(status_code=200, json=lambda: fake_body)
            interactions = session.poll()
        self.assertEqual(len(interactions), 1)
        self.assertEqual(interactions[0]['full-id'], 'aaaa.c.oast.pro')


class TestDeregister(unittest.TestCase):

    def test_deregister_without_registration_makes_no_request(self):
        session = InteractshSession()
        with patch('modules.pentesting.interactsh_client.requests.post') as mock_post:
            session.deregister()
        mock_post.assert_not_called()

    def test_deregister_sends_correlation_id_and_secret(self):
        session = InteractshSession()
        with patch('modules.pentesting.interactsh_client.requests.post') as mock_post:
            mock_post.return_value = MagicMock(status_code=200)
            session.register()
        with patch('modules.pentesting.interactsh_client.requests.post') as mock_post2:
            mock_post2.return_value = MagicMock(status_code=200)
            session.deregister()
        _, kwargs = mock_post2.call_args
        self.assertEqual(kwargs['json']['correlation-id'], session.correlation_id)
        self.assertFalse(session.registered)

    def test_deregister_swallows_network_errors(self):
        session = InteractshSession()
        with patch('modules.pentesting.interactsh_client.requests.post') as mock_post:
            mock_post.return_value = MagicMock(status_code=200)
            session.register()
        with patch('modules.pentesting.interactsh_client.requests.post',
                   side_effect=requests.exceptions.ConnectionError("down")):
            session.deregister()  # No debe lanzar.
        self.assertFalse(session.registered)


if __name__ == '__main__':
    unittest.main()
