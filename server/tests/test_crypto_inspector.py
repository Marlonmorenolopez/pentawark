"""
Pruebas del inspector de material criptográfico de Code Scan.

Todo el material se GENERA en cada ejecución (nunca llaves reales del proyecto).
Solo `unittest` (convención del proyecto). Ejecutar:
    cd server && python3 -m unittest tests.test_crypto_inspector
"""

import datetime as dt
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from cryptography import x509                                                    # noqa: E402
from cryptography.hazmat.primitives import hashes, serialization as ser         # noqa: E402
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa  # noqa: E402
from cryptography.hazmat.primitives.serialization import pkcs12                  # noqa: E402
from cryptography.x509.oid import NameOID                                       # noqa: E402

from modules.code_security.crypto_inspector import CryptoKeyScanner             # noqa: E402
from modules.code_security.crypto_inspector import analyze as an                # noqa: E402
from modules.code_security.crypto_inspector import detect as det                # noqa: E402
from modules.code_security.crypto_inspector import export as ex                 # noqa: E402
from modules.code_security.crypto_inspector import openssl_ref as ossl          # noqa: E402
from modules.code_security.crypto_inspector import service as svc               # noqa: E402
from modules.code_security.crypto_inspector.vault import Vault                  # noqa: E402
from modules.code_security.orchestrator import CodeScanOrchestrator             # noqa: E402
import findings as findings_module                                              # noqa: E402

PW = b'Lab-Only-Pw-123'
HAS_OPENSSL = shutil.which('openssl') is not None


# ── generación de material de laboratorio ─────────────────────────────────────
def pem_priv(key, fmt=ser.PrivateFormat.PKCS8, enc=None):
    return key.private_bytes(ser.Encoding.PEM, fmt, enc or ser.NoEncryption())


def pem_pub(key):
    return key.public_key().public_bytes(ser.Encoding.PEM, ser.PublicFormat.SubjectPublicKeyInfo)


def make_cert(key, days=365, sign_hash=hashes.SHA256(), cn='lab.example.test'):
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = dt.datetime.now(dt.timezone.utc)
    return (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(days=abs(days) + 10 if days < 0 else 1))
            .not_valid_after(now + dt.timedelta(days=days))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(cn), x509.DNSName('www.' + cn)]), critical=False)
            .sign(key, sign_hash))


class Lab:
    """Directorio temporal con material generado."""
    def __init__(self):
        self.dir = tempfile.mkdtemp(prefix='cryptolab-')

    def put(self, rel, data):
        p = Path(self.dir) / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data if isinstance(data, bytes) else data.encode())
        return p

    def scan(self):
        return CryptoKeyScanner().scan(self.dir)

    def cleanup(self):
        shutil.rmtree(self.dir, ignore_errors=True)


def by_file(result):
    return {i['file']: i for i in result['items']}


def rsa_key(bits):
    return rsa.generate_private_key(65537, bits)


# ── 1. identificación de algoritmo / formato / tipo ──────────────────────────
class TestIdentification(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.lab = Lab()
        cls.rsa1024, cls.rsa2048, cls.rsa3072 = rsa_key(1024), rsa_key(2048), rsa_key(3072)
        cls.ec = ec.generate_private_key(ec.SECP256R1())
        cls.ed = ed25519.Ed25519PrivateKey.generate()
        cls.ed4 = ed448.Ed448PrivateKey.generate()
        cls.dsa = dsa.generate_private_key(1024)
        L = cls.lab
        L.put('k/rsa1024.key', pem_priv(cls.rsa1024, ser.PrivateFormat.TraditionalOpenSSL))
        L.put('k/rsa2048.key', pem_priv(cls.rsa2048))
        L.put('k/rsa3072.key', pem_priv(cls.rsa3072))
        L.put('k/ec.key', pem_priv(cls.ec, ser.PrivateFormat.TraditionalOpenSSL))
        L.put('k/ed25519.key', pem_priv(cls.ed))
        L.put('k/ed448.key', pem_priv(cls.ed4))
        L.put('k/dsa.key', pem_priv(cls.dsa, ser.PrivateFormat.TraditionalOpenSSL))
        L.put('k/rsa2048.pub', pem_pub(cls.rsa2048))
        L.put('k/rsa2048.der', cls.rsa2048.private_bytes(ser.Encoding.DER, ser.PrivateFormat.PKCS8, ser.NoEncryption()))
        L.put('k/rsa2048pub.der', cls.rsa2048.public_key().public_bytes(ser.Encoding.DER, ser.PublicFormat.SubjectPublicKeyInfo))
        L.put('k/id_ed25519', cls.ed.private_bytes(ser.Encoding.PEM, ser.PrivateFormat.OpenSSH, ser.NoEncryption()))
        L.put('k/id_ed25519.pub', cls.ed.public_key().public_bytes(ser.Encoding.OpenSSH, ser.PublicFormat.OpenSSH) + b' lab@test\n')
        cls.cert = make_cert(cls.rsa2048)
        L.put('k/server.crt', cls.cert.public_bytes(ser.Encoding.PEM))
        L.put('k/server.der', cls.cert.public_bytes(ser.Encoding.DER))
        cls.res = L.scan()
        cls.items = by_file(cls.res)

    @classmethod
    def tearDownClass(cls):
        cls.lab.cleanup()

    def test_rsa_sizes_and_encodings(self):
        for name, bits, enc in (('rsa1024.key', 1024, 'PKCS#1'), ('rsa2048.key', 2048, 'PKCS#8'), ('rsa3072.key', 3072, 'PKCS#8')):
            it = self.items['k/' + name]
            self.assertEqual((it['algorithm'], it['key_size'], it['material_type'], it['format'], it['encoding']),
                             ('RSA', bits, 'private_key', 'PEM', enc), name)
            self.assertEqual(it['protection'], 'none')

    def test_weak_rsa_flagged_but_not_strong(self):
        self.assertIn('rsa_key_too_small', [w['code'] for w in self.items['k/rsa1024.key']['weaknesses']])
        self.assertEqual(self.items['k/rsa1024.key']['status'], an.S_WEAK)
        self.assertNotIn('rsa_key_too_small', [w['code'] for w in self.items['k/rsa2048.key']['weaknesses']])
        self.assertEqual(self.items['k/rsa2048.key']['status'], an.S_COMPLETED)   # válida != segura, pero aquí no hay debilidad

    def test_ec_ed_dsa(self):
        self.assertEqual((self.items['k/ec.key']['algorithm'], self.items['k/ec.key']['curve'], self.items['k/ec.key']['encoding']),
                         ('EC', 'secp256r1', 'SEC1'))
        self.assertEqual(self.items['k/ed25519.key']['algorithm'], 'Ed25519')
        self.assertEqual(self.items['k/ed448.key']['algorithm'], 'Ed448')
        d = self.items['k/dsa.key']
        self.assertEqual((d['algorithm'], d['key_size']), ('DSA', 1024))
        self.assertTrue({'dsa_deprecated', 'dsa_key_too_small'} <= {w['code'] for w in d['weaknesses']})

    def test_public_keys_and_der(self):
        self.assertEqual(self.items['k/rsa2048.pub']['material_type'], 'public_key')
        self.assertEqual(self.items['k/rsa2048.pub']['encoding'], 'SubjectPublicKeyInfo')
        der_priv = self.items['k/rsa2048.der']
        self.assertEqual((der_priv['format'], der_priv['material_type'], der_priv['algorithm']), ('DER', 'private_key', 'RSA'))
        self.assertEqual((self.items['k/rsa2048pub.der']['format'], self.items['k/rsa2048pub.der']['material_type']), ('DER', 'public_key'))
        # sin parte privada: jamás aparece exposición
        self.assertEqual([w for w in self.items['k/rsa2048.pub']['weaknesses'] if w['kind'] == 'possible_exposure'], [])

    def test_openssh(self):
        priv, pub = self.items['k/id_ed25519'], self.items['k/id_ed25519.pub']
        self.assertEqual((priv['format'], priv['encoding'], priv['algorithm'], priv['material_type']), ('PEM', 'OpenSSH', 'Ed25519', 'private_key'))
        self.assertEqual((pub['format'], pub['material_type'], pub['algorithm']), ('OpenSSH', 'public_key', 'Ed25519'))

    def test_certificates_not_confused_with_private_keys(self):
        for rel, fmt in (('k/server.crt', 'PEM'), ('k/server.der', 'DER')):
            it = self.items[rel]
            self.assertEqual((it['material_type'], it['format'], it['algorithm'], it['key_size']), ('certificate', fmt, 'RSA', 2048))
            self.assertEqual(it['cert']['dns_names'], ['lab.example.test', 'www.lab.example.test'])
            self.assertEqual([w for w in it['weaknesses'] if w['kind'] == 'possible_exposure'], [])
            c = it['cert']['checks']
            self.assertEqual((c['structure_valid'], c['validity_period'], c['chain_trust']), (True, 'valid', 'not_evaluated'))

    def test_cert_matches_private_key_in_same_scan(self):
        crt, key = self.items['k/server.crt'], self.items['k/rsa2048.key']
        self.assertEqual(crt['cert']['checks']['private_key_match'], 'match')
        self.assertIn(key['id'], crt['matches'])
        self.assertEqual(self.items['k/server.crt']['fingerprint'], key['fingerprint'])

    def test_context_lowers_exposure_severity(self):
        lab = Lab()
        try:
            k = pem_priv(self.rsa2048)
            lab.put('src/prod.key', k)
            lab.put('tests/fixtures/t.key', k)
            lab.put('node_modules/pkg/test/x.key', k)
            r = by_file(lab.scan())
            sev = {f: [w['severity'] for w in i['weaknesses'] if w['kind'] == 'possible_exposure'][0] for f, i in r.items()}
            self.assertEqual(sev['src/prod.key'], 'medium')
            self.assertEqual(sev['tests/fixtures/t.key'], 'low')
            self.assertEqual(sev['node_modules/pkg/test/x.key'], 'low')
            self.assertEqual(r['src/prod.key']['context'], 'project')
        finally:
            lab.cleanup()

    def test_no_claim_of_confirmed_exposure_or_active_use(self):
        for it in self.res['items']:
            self.assertEqual(it['assessment'], {'confirmed_exposure': None, 'active_use': None})

    def test_openssl_cross_check_recorded_only_when_invoked(self):
        it = self.items['k/rsa2048.key']
        names = [t['tool'] for t in it['tools']]
        self.assertIn('cryptography', names)
        if HAS_OPENSSL:
            o = [t for t in it['tools'] if t['tool'] == 'openssl'][0]
            self.assertEqual(o['result'], 'match')
            self.assertTrue(o['version'].startswith('OpenSSL'))


# ── 2. cifrado / contraseña ───────────────────────────────────────────────────
class TestEncryption(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.key = rsa_key(2048)
        cls.lab = Lab()
        L = cls.lab
        L.put('enc/pkcs8.key', pem_priv(cls.key, enc=ser.BestAvailableEncryption(PW)))
        L.put('enc/legacy.key', pem_priv(cls.key, ser.PrivateFormat.TraditionalOpenSSL, ser.BestAvailableEncryption(PW)))
        ed = ed25519.Ed25519PrivateKey.generate()
        cls.has_ssh_enc = True
        try:  # el cifrado OpenSSH requiere el módulo opcional bcrypt (no es dependencia del proyecto)
            L.put('enc/ssh_enc', ed.private_bytes(ser.Encoding.PEM, ser.PrivateFormat.OpenSSH, ser.BestAvailableEncryption(PW)))
        except Exception:  # noqa: BLE001
            cls.has_ssh_enc = False
        cert = make_cert(cls.key)
        L.put('enc/bundle.p12', pkcs12.serialize_key_and_certificates(b'lab', cls.key, cert, None, ser.BestAvailableEncryption(PW)))
        L.put('enc/pkcs8.der', cls.key.private_bytes(ser.Encoding.DER, ser.PrivateFormat.PKCS8, ser.BestAvailableEncryption(PW)))
        cls.res = L.scan()
        cls.items = by_file(cls.res)
        cls.blobs = {i['id']: b for i, b in ()}

    @classmethod
    def tearDownClass(cls):
        cls.lab.cleanup()

    def test_encrypted_without_password_is_not_marked_decrypted(self):
        for rel in ('enc/pkcs8.key', 'enc/legacy.key', 'enc/ssh_enc', 'enc/pkcs8.der'):
            if rel == 'enc/ssh_enc' and not self.has_ssh_enc:
                continue  # sin bcrypt no se puede generar el material de laboratorio: no se afirma nada
            it = self.items[rel]
            self.assertEqual(it['status'], an.S_NEEDS_PASSWORD, rel)
            self.assertEqual(it['protection'], 'encrypted', rel)
            self.assertNotEqual(it['detail_code'], 'decrypted_with_user_password', rel)
            self.assertIsNone(it['fingerprint'], rel)
        self.assertIsNotNone(self.items['enc/legacy.key']['cipher'])          # DEK-Info visible sin descifrar
        self.assertEqual(self.items['enc/legacy.key']['algorithm'], 'RSA')    # la etiqueta PEM lo dice

    def test_pkcs12_is_container_needing_password(self):
        it = self.items['enc/bundle.p12']
        self.assertEqual((it['material_type'], it['status'], it['protection']), ('pkcs12', an.S_NEEDS_PASSWORD, 'password-container'))

    def test_encrypted_is_not_reported_as_invalid(self):
        for it in self.items.values():
            self.assertNotEqual(it['status'], an.S_INVALID)

    def test_with_user_password_and_wrong_password(self):
        raw = (Path(self.lab.dir) / 'enc/pkcs8.key').read_bytes()
        ok = an.analyze(raw, 'PEM', 'ENCRYPTED PRIVATE KEY', password=PW, with_params=True)
        self.assertEqual(ok['status'], an.S_COMPLETED)
        self.assertEqual(ok['detail_code'], 'decrypted_with_user_password')
        bad = an.analyze(raw, 'PEM', 'ENCRYPTED PRIVATE KEY', password=b'otra', with_params=True)
        self.assertEqual((bad['status'], bad['detail_code']), (an.S_NEEDS_PASSWORD, 'wrong_password'))
        self.assertNotIn('private_params', bad)
        for rel, label in (('enc/legacy.key', 'RSA PRIVATE KEY'), ('enc/ssh_enc', 'OPENSSH PRIVATE KEY')):
            if rel == 'enc/ssh_enc' and not self.has_ssh_enc:
                continue
            r = (Path(self.lab.dir) / rel).read_bytes()
            self.assertEqual(an.analyze(r, 'PEM', label, password=PW, with_params=True)['status'], an.S_COMPLETED, rel)
        p12 = (Path(self.lab.dir) / 'enc/bundle.p12').read_bytes()
        self.assertEqual(an.analyze(p12, 'DER', None, password=PW, with_params=True)['status'], an.S_COMPLETED)
        der = (Path(self.lab.dir) / 'enc/pkcs8.der').read_bytes()
        self.assertEqual(an.analyze(der, 'DER', None, password=PW, with_params=True)['status'], an.S_COMPLETED)

    def test_password_for_unencrypted_key_is_harmless(self):
        raw = pem_priv(self.key)
        self.assertEqual(an.analyze(raw, 'PEM', 'PRIVATE KEY', password=b'x')['status'], an.S_COMPLETED)


# ── 3. archivos inválidos / no compatibles / límites ─────────────────────────
class TestEdgeCases(unittest.TestCase):
    def setUp(self):
        self.lab = Lab()

    def tearDown(self):
        self.lab.cleanup()

    def test_corrupt_is_invalid_not_encrypted_and_not_a_vulnerability(self):
        self.lab.put('bad.pem', '-----BEGIN RSA PRIVATE KEY-----\nAAAA\n-----END RSA PRIVATE KEY-----\n')
        it = by_file(self.lab.scan())['bad.pem']
        self.assertEqual(it['status'], an.S_INVALID)
        self.assertEqual(it['weaknesses'], [])
        self.assertIsNone(it['risk'])

    def test_corrupt_pem_cert_and_truncated_der(self):
        self.lab.put('c.crt', '-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n')
        r = by_file(self.lab.scan())
        self.assertEqual(r['c.crt']['status'], an.S_INVALID)

    def test_files_without_crypto_material(self):
        self.lab.put('README.md', '# nada que ver\n' * 20)
        self.lab.put('data.bin', bytes(range(256)) * 4)
        self.lab.put('code.js', 'const a = "hola";\n' * 10)
        r = self.lab.scan()
        self.assertEqual(r['items'], [])
        self.assertEqual(r['status'], 'completed')

    def test_unsupported_formats(self):
        self.lab.put('dh.pem', '-----BEGIN DH PARAMETERS-----\nMIIBCAKCAQEA\n-----END DH PARAMETERS-----\n')
        csr_key = rsa_key(2048)
        csr = (x509.CertificateSigningRequestBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'x')]))
               .sign(csr_key, hashes.SHA256()))
        self.lab.put('req.csr', csr.public_bytes(ser.Encoding.PEM))
        r = by_file(self.lab.scan())
        for rel in ('dh.pem', 'req.csr'):
            self.assertEqual(r[rel]['status'], an.S_UNSUPPORTED_FORMAT, rel)
            self.assertEqual(r[rel]['weaknesses'], [], rel)

    def test_unsupported_algorithm_status(self):
        with mock.patch.object(an.serialization, 'load_pem_private_key', side_effect=an.UnsupportedAlgorithm('x')):
            res = an.analyze(b'-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----', 'PEM', 'PRIVATE KEY')
        self.assertEqual(res['status'], an.S_UNSUPPORTED_ALGORITHM)

    def test_oversized_files_are_ignored(self):
        big = pem_priv(rsa_key(2048)) + b'\n' + b'#' * (det.MAX_FILE_BYTES + 10)
        self.lab.put('huge.key', big)
        self.assertEqual(self.lab.scan()['items'], [])

    def test_symlinks_are_not_followed(self):
        outside = tempfile.mkdtemp()
        try:
            Path(outside, 'secret.key').write_bytes(pem_priv(rsa_key(2048)))
            os.symlink(Path(outside, 'secret.key'), Path(self.lab.dir, 'link.key'))
            self.assertEqual(self.lab.scan()['items'], [])
        finally:
            shutil.rmtree(outside, ignore_errors=True)

    def test_multiple_blocks_in_one_file(self):
        k = rsa_key(2048)
        cert = make_cert(k)
        self.lab.put('bundle.pem', pem_priv(k) + cert.public_bytes(ser.Encoding.PEM) + cert.public_bytes(ser.Encoding.PEM))
        items = self.lab.scan()['items']
        self.assertEqual(sorted(i['material_type'] for i in items), ['certificate', 'certificate', 'private_key'])
        self.assertEqual(len({i['id'] for i in items}), 3)

    def test_candidate_cap_is_reported(self):
        k = pem_priv(rsa_key(2048))
        with mock.patch.object(det, 'MAX_CANDIDATES', 3):
            for n in range(6):
                self.lab.put(f'k{n}.key', k)
            r = self.lab.scan()
        self.assertEqual(len(r['items']), 3)
        self.assertEqual(r['truncated'], 'candidates')
        self.assertIn('límite', r['warning'])

    def test_permission_failure_does_not_abort(self):
        self.lab.put('a.key', pem_priv(rsa_key(2048)))
        real_open = open

        def deny(path, *a, **kw):
            if str(path).endswith('a.key'):
                raise PermissionError('denied')
            return real_open(path, *a, **kw)

        with mock.patch('builtins.open', side_effect=deny):
            r = self.lab.scan()
        self.assertEqual((r['status'], r['items']), ('completed', []))

    def test_expired_and_expiring_and_weak_signature_certs(self):
        k = rsa_key(2048)
        self.lab.put('exp.crt', make_cert(k, days=-30).public_bytes(ser.Encoding.PEM))
        self.lab.put('soon.crt', make_cert(k, days=10).public_bytes(ser.Encoding.PEM))
        has_sha1 = True
        try:  # versiones recientes de cryptography/OpenSSL se niegan a firmar con SHA-1
            self.lab.put('sha1.crt', make_cert(k, sign_hash=hashes.SHA1()).public_bytes(ser.Encoding.PEM))
        except Exception:  # noqa: BLE001
            has_sha1 = False
        r = by_file(self.lab.scan())
        self.assertIn('cert_expired', [w['code'] for w in r['exp.crt']['weaknesses']])
        self.assertIn('cert_expiring_soon', [w['code'] for w in r['soon.crt']['weaknesses']])
        if has_sha1:
            self.assertIn('cert_weak_signature', [w['code'] for w in r['sha1.crt']['weaknesses']])
        self.assertEqual(r['exp.crt']['cert']['checks']['validity_period'], 'expired')


# ── 4. herramientas ausentes / errores ───────────────────────────────────────
class TestToolFailures(unittest.TestCase):
    def setUp(self):
        self.lab = Lab()
        self.lab.put('a.key', pem_priv(rsa_key(2048)))

    def tearDown(self):
        self.lab.cleanup()

    def test_openssl_missing_is_reported_and_alternative_used(self):
        with mock.patch.object(ossl, 'binary', return_value=None):
            r = self.lab.scan()
        it = r['items'][0]
        o = [t for t in it['tools'] if t['tool'] == 'openssl'][0]
        self.assertEqual(o['result'], 'unavailable')
        self.assertIn('cryptography', o['alternative'])
        self.assertEqual(it['status'], an.S_COMPLETED)           # un fallo de herramienta NO es una vulnerabilidad
        self.assertFalse([t for t in r['tools'] if t['tool'] == 'openssl'][0]['available'])

    def test_cryptography_missing(self):
        with mock.patch.object(an, 'CRYPTO_AVAILABLE', False):
            res = an.analyze(b'x', 'PEM', 'PRIVATE KEY')
            scan = CryptoKeyScanner().scan(self.lab.dir)
        self.assertEqual(res['status'], an.S_TOOL_UNAVAILABLE)
        self.assertEqual(scan['status'], 'skipped')
        self.assertEqual(scan['items'], [])

    def test_library_error_gives_clear_status_without_leaking(self):
        with mock.patch.object(an, '_analyze_pem', side_effect=RuntimeError('BEGIN RSA PRIVATE KEY MIIE-secreto')):
            res = an.analyze(b'x', 'PEM', 'PRIVATE KEY')
        self.assertEqual(res['status'], an.S_ERROR)
        self.assertNotIn('secreto', json.dumps(res))
        self.assertEqual(res['weaknesses'] if 'weaknesses' in res else [], [])

    def test_openssl_failure_not_converted_into_finding(self):
        with mock.patch.object(ossl, '_run', return_value=None):
            r = self.lab.scan()
        o = [t for t in r['items'][0]['tools'] if t['tool'] == 'openssl'][0]
        self.assertEqual(o['result'], 'error')
        self.assertNotIn('rsa_key_too_small', [w['code'] for w in r['items'][0]['weaknesses']])


# ── 5. parámetros: coinciden con OpenSSL y no se truncan ──────────────────────
def _openssl_rsa_text(path):
    out = subprocess.run(['openssl', 'rsa', '-in', path, '-text', '-noout'], capture_output=True, check=True).stdout.decode()
    fields, cur = {}, None
    for line in out.splitlines():
        m = re.match(r'^([A-Za-z0-9]+):\s*(.*)$', line)
        if m:
            cur = m.group(1)
            fields[cur] = m.group(2)
        elif cur and line.startswith(' '):
            fields[cur] += line.strip()
    clean = {}
    for k, v in fields.items():
        h = re.sub(r'[^0-9a-f]', '', v.lower())
        clean[k] = h.lstrip('0') or '0'
    return clean


class TestParameters(unittest.TestCase):
    def test_rsa_parameters_complete_and_match_openssl(self):
        if not HAS_OPENSSL:
            self.skipTest('openssl no disponible: no hay herramienta de referencia')
        key = rsa_key(2048)
        raw = pem_priv(key, ser.PrivateFormat.TraditionalOpenSSL)
        res = an.analyze(raw, 'PEM', 'RSA PRIVATE KEY', with_params=True)
        params = {p['name']: p for p in res['public_params'] + res['private_params']}
        self.assertEqual({'n', 'e', 'd', 'p', 'q', 'dP', 'dQ', 'qInv'}, set(params))
        self.assertEqual({params[k]['kind'] for k in ('n', 'e')}, {'public'})
        self.assertEqual({params[k]['kind'] for k in ('d', 'p', 'q', 'dP', 'dQ', 'qInv')}, {'private'})
        with tempfile.NamedTemporaryFile(suffix='.key', delete=False) as f:
            f.write(raw)
        try:
            ref = _openssl_rsa_text(f.name)
        finally:
            os.unlink(f.name)
        mapping = {'n': 'modulus', 'd': 'privateExponent', 'p': 'prime1', 'q': 'prime2',
                   'dP': 'exponent1', 'dQ': 'exponent2', 'qInv': 'coefficient'}
        for ours, theirs in mapping.items():
            self.assertEqual(params[ours]['hex'].lstrip('0') or '0', ref[theirs], ours)
        self.assertEqual(int(params['e']['hex'], 16), 65537)

    def test_values_not_truncated(self):
        key = rsa_key(3072)
        res = an.analyze(pem_priv(key), 'PEM', 'PRIVATE KEY', with_params=True)
        n = [p for p in res['public_params'] if p['name'] == 'n'][0]
        self.assertEqual(int(n['hex'], 16), key.public_key().public_numbers().n)
        self.assertGreaterEqual(len(n['hex']), 768)                       # 3072 bits = 768 hex
        self.assertNotIn('…', n['hex'])
        self.assertNotIn('*', n['hex'])

    def test_other_algorithms_expose_their_own_structure(self):
        e = an.analyze(pem_priv(ec.generate_private_key(ec.SECP384R1())), 'PEM', 'PRIVATE KEY', with_params=True)
        self.assertEqual([p['name'] for p in e['public_params']], ['x', 'y'])
        self.assertEqual([p['name'] for p in e['private_params']], ['d'])
        ed = an.analyze(pem_priv(ed25519.Ed25519PrivateKey.generate()), 'PEM', 'PRIVATE KEY', with_params=True)
        self.assertEqual([p['name'] for p in ed['private_params']], ['private_bytes'])
        self.assertEqual(len(ed['private_params'][0]['hex']), 64)
        d = an.analyze(pem_priv(dsa.generate_private_key(1024), ser.PrivateFormat.TraditionalOpenSSL), 'PEM', 'DSA PRIVATE KEY', with_params=True)
        self.assertEqual([p['name'] for p in d['public_params']], ['p', 'q', 'g', 'y'])

    def test_public_key_never_shows_private_params(self):
        res = an.analyze(pem_pub(rsa_key(2048)), 'PEM', 'PUBLIC KEY', with_params=True)
        self.assertEqual(res['private_params'], [])
        self.assertEqual({p['name'] for p in res['public_params']}, {'n', 'e'})

    def test_params_only_when_requested(self):
        res = an.analyze(pem_priv(rsa_key(2048)), 'PEM', 'PRIVATE KEY')
        self.assertNotIn('private_params', res)
        self.assertNotIn('public_params', res)


# ── 6. protección de secretos ─────────────────────────────────────────────────
class TestSecretProtection(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.key = rsa_key(2048)
        cls.lab = Lab()
        cls.pem = pem_priv(cls.key)
        cls.lab.put('s/plain.key', cls.pem)
        cls.lab.put('s/enc.key', pem_priv(cls.key, enc=ser.BestAvailableEncryption(PW)))
        cls.res = cls.lab.scan()
        nums = cls.key.private_numbers()
        cls.secrets = [format(nums.d, 'x'), format(nums.p, 'x'), format(nums.q, 'x'),
                       cls.pem.decode().split('\n')[1][:40], PW.decode()]

    @classmethod
    def tearDownClass(cls):
        cls.lab.cleanup()

    def _persistable(self):
        return json.dumps({k: v for k, v in self.res.items() if k != '_blobs'})

    def test_record_to_persist_has_no_private_material(self):
        text = self._persistable()
        for s in self.secrets:
            self.assertNotIn(s, text)
        self.assertNotIn('BEGIN', text)
        self.assertNotIn('private_params', text)

    def test_findings_and_logs_are_clean(self):
        with self.assertLogs(level='DEBUG') as cm:
            import logging
            logging.getLogger('x').debug('marker')
            CryptoKeyScanner().scan(self.lab.dir)
        logs = '\n'.join(cm.output)
        for s in self.secrets:
            self.assertNotIn(s, logs)
        for f in self.res['findings']:
            for s in self.secrets:
                self.assertNotIn(s, json.dumps(f))

    def test_orchestrator_drops_blobs_even_without_callback(self):
        o = CodeScanOrchestrator.__new__(CodeScanOrchestrator)
        class _F:
            def __init__(self, r): self.r = r
            def scan(self, p): return dict(self.r)
        for k in ('gitleaks', 'trufflehog', 'backdoors', 'semgrep', 'trivy', 'dependency_check'):
            setattr(o, k, _F({'findings': [], 'error': None}))
        o.crypto_keys = CryptoKeyScanner()
        out = o.scan_directory(self.lab.dir)
        self.assertNotIn('_blobs', out['crypto_keys'])
        self.assertEqual(out['summary']['tools_total'], 7)
        self.assertGreater(out['summary']['medium'], 0)       # los hallazgos criptográficos entran al resumen
        self.assertIn('crypto_keys', out['tools'])
        self.assertNotIn('BEGIN', json.dumps(out))

    def test_findings_pipeline_includes_crypto(self):
        scan = {'scan_type': 'code', 'crypto_keys': {k: v for k, v in self.res.items() if k != '_blobs'}}
        fs = findings_module.normalize_findings(scan)
        self.assertTrue(fs and all(f['tool'] == 'crypto_keys' for f in fs))
        self.assertNotIn('BEGIN', json.dumps(fs))


# ── 7. custodia (vault) ───────────────────────────────────────────────────────
class _FakeRedis:
    def __init__(self):
        self.d = {}

    def setex(self, k, ttl, v):
        self.d[k] = (ttl, v)

    def get(self, k):
        return self.d.get(k, (0, None))[1]


class TestVault(unittest.TestCase):
    def key(self):
        from cryptography.fernet import Fernet
        return Fernet.generate_key().decode()

    def test_roundtrip_and_encrypted_at_rest(self):
        r = _FakeRedis()
        v = Vault(lambda: r, key=self.key(), ttl=600)
        secret = b'-----BEGIN PRIVATE KEY-----\nTOPSECRETBODY\n-----END PRIVATE KEY-----'
        self.assertTrue(v.put('scan1', 'item1', secret))
        stored = list(r.d.values())[0]
        self.assertEqual(stored[0], 600)                        # caducidad
        self.assertNotIn(b'TOPSECRETBODY', stored[1])           # cifrado en reposo
        self.assertEqual(v.get('scan1', 'item1'), secret)
        self.assertIsNone(v.get('scan1', 'otro'))

    def test_disabled_without_or_with_invalid_key(self):
        for key in ('', 'no-es-una-clave-fernet'):
            v = Vault(lambda: None, key=key)
            self.assertFalse(v.enabled)
            self.assertFalse(v.put('s', 'i', b'x'))
            self.assertIsNone(v.get('s', 'i'))

    def test_memory_fallback_and_expiry(self):
        v = Vault(lambda: None, key=self.key(), ttl=3600)
        v.put('s', 'i', b'abc')
        self.assertEqual(v.get('s', 'i'), b'abc')
        v2 = Vault(lambda: None, key=self.key(), ttl=-1)
        v2.put('s', 'i', b'abc')
        self.assertIsNone(v2.get('s', 'i'))

    def test_wrong_key_cannot_read(self):
        r = _FakeRedis()
        Vault(lambda: r, key=self.key()).put('s', 'i', b'abc')
        self.assertIsNone(Vault(lambda: r, key=self.key()).get('s', 'i'))

    def test_redis_down_falls_back(self):
        class Down:
            def setex(self, *a): raise ConnectionError('x')
            def get(self, *a): raise ConnectionError('x')
        v = Vault(lambda: Down(), key=self.key())
        self.assertTrue(v.put('s', 'i', b'abc'))
        self.assertEqual(v.get('s', 'i'), b'abc')


# ── 8. servicio (lógica de las rutas) y exportación ───────────────────────────
class TestServiceAndExport(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from cryptography.fernet import Fernet
        cls.key = rsa_key(2048)
        cls.lab = Lab()
        cls.lab.put('p/plain.key', pem_priv(cls.key))
        cls.lab.put('p/enc.key', pem_priv(cls.key, enc=ser.BestAvailableEncryption(PW)))
        cls.lab.put('p/pub.pem', pem_pub(cls.key))
        cls.vault = Vault(lambda: None, key=Fernet.generate_key().decode())
        res = CryptoKeyScanner().scan(cls.lab.dir)
        blobs = res.pop('_blobs')
        for it in res['items']:
            it['inspectable'] = cls.vault.put('SCAN', it['id'], blobs[it['id']])
        cls.scan = {'id': 'abcd1234-0000-4000-8000-000000000000', 'source': 'lab', 'crypto_keys': res}
        cls.items = by_file(res)

    @classmethod
    def tearDownClass(cls):
        cls.lab.cleanup()

    def test_gate(self):
        self.assertEqual(svc.private_gate(False, False, True), (403, 'token_required'))
        self.assertEqual(svc.private_gate(True, False, False), (503, 'vault_disabled'))
        self.assertIsNone(svc.private_gate(True, False, True))
        self.assertIsNone(svc.private_gate(False, True, True))        # excepción explícita de laboratorio

    def test_password_parsing(self):
        self.assertEqual(svc.parse_password(None), (None, False))
        self.assertEqual(svc.parse_password('abc'), (b'abc', False))
        self.assertEqual(svc.parse_password(123), (None, True))
        self.assertEqual(svc.parse_password('x' * 1000), (None, True))

    def test_inspect_returns_private_params_only_on_request_path(self):
        st, body = svc.inspect_item(self.vault, 'SCAN', self.items['p/plain.key'], None)
        self.assertEqual((st, body['status']), (200, an.S_COMPLETED))
        self.assertEqual({p['name'] for p in body['private_params']}, {'d', 'p', 'q', 'dP', 'dQ', 'qInv'})

    def test_inspect_encrypted_flow(self):
        it = self.items['p/enc.key']
        st, body = svc.inspect_item(self.vault, 'SCAN', it, None)
        self.assertEqual(body['status'], an.S_NEEDS_PASSWORD)
        self.assertEqual(body['private_params'], [])
        st, body = svc.inspect_item(self.vault, 'SCAN', it, PW)
        self.assertEqual(body['status'], an.S_COMPLETED)
        self.assertTrue(body['private_params'])

    def test_inspect_expired(self):
        st, body = svc.inspect_item(self.vault, 'OTRO-SCAN', self.items['p/plain.key'], None)
        self.assertEqual((st, body['code']), (410, 'expired'))

    def test_technical_report_has_no_private_material_or_passwords(self):
        rep = ex.technical_report(self.scan, 'es')
        text = ex.render(rep, 'json') + ex.render(rep, 'txt')
        n = self.key.private_numbers()
        for s in (format(n.d, 'x'), format(n.p, 'x'), PW.decode(), 'BEGIN'):
            self.assertNotIn(s, text)
        self.assertFalse(rep['includes_private_material'])
        self.assertNotIn('private_parameters', text)
        self.assertTrue(rep['limitations'])

    def test_full_export_contains_only_recovered_values_and_no_passwords(self):
        params = svc.collect_full_params(self.vault, 'SCAN', self.scan, None, {self.items['p/enc.key']['id']: PW.decode()})
        rep = ex.full_export(self.scan, params, 'es')
        text = ex.render(rep, 'json')
        n = self.key.private_numbers()
        self.assertIn(format(n.d, 'x'), text)
        self.assertNotIn(PW.decode(), text)                              # la contraseña no se exporta
        by = {v['file']: v for v in rep['items']}
        self.assertIn('private_parameters', by['p/plain.key'])
        self.assertIn('private_parameters', by['p/enc.key'])            # con su contraseña se pudo abrir
        self.assertNotIn('private_parameters', by['p/pub.pem'])         # una pública jamás se presenta como privada
        self.assertTrue(rep['includes_private_material'])
        self.assertIn('secretos', rep['warning'])
        # sin contraseña, la cifrada NO aparece como recuperada
        params2 = svc.collect_full_params(self.vault, 'SCAN', self.scan, None, {})
        rep2 = ex.full_export(self.scan, params2, 'en')
        by2 = {v['file']: v for v in rep2['items']}
        self.assertNotIn('private_parameters', by2['p/enc.key'])
        self.assertEqual(by2['p/enc.key']['recovery']['status'], an.S_NEEDS_PASSWORD)

    def test_full_export_item_filter(self):
        only = self.items['p/plain.key']['id']
        params = svc.collect_full_params(self.vault, 'SCAN', self.scan, [only], {})
        self.assertEqual(list(params), [only])

    def test_safe_filename(self):
        n = ex.safe_filename('../../etc/passwd', 'full', 'json')
        self.assertRegex(n, r'^crypto-full-[a-f0-9]{0,8}-?[a-z0-9-]*\.json$|^crypto-full-scan-\d{8}-\d{6}\.json$')
        self.assertNotIn('/', n)
        self.assertNotIn('..', n)
        self.assertTrue(ex.safe_filename('a' * 8, 'raro', 'exe').endswith('.json'))

    def test_texts_are_translated_both_languages(self):
        es = ex.technical_report(self.scan, 'es')['items']
        en = ex.technical_report(self.scan, 'en')['items']
        t = lambda items: ' '.join(w['title'] for i in items for w in i['weaknesses'])
        self.assertIn('Llave privada', t(es))
        self.assertIn('Unprotected private key', t(en))


if __name__ == '__main__':
    unittest.main()
