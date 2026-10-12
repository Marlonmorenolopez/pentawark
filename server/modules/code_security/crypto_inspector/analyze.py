"""
Análisis de material criptográfico (llaves, certificados, contenedores).

Método principal: la biblioteca Python `cryptography` (ya es dependencia del
proyecto). OpenSSL se usa APARTE y solo como contraste (ver openssl_ref.py).

Terminología (no mezclar):
  - Inspeccionar / decodificar: leer la estructura (no requiere secreto).
  - Extraer parámetros: obtener los números de la llave.
  - Descifrar una llave protegida: usar la contraseña que ENTREGA el usuario.
    Este módulo NO prueba contraseñas ni hace fuerza bruta.

Nunca se ejecuta nada del archivo analizado ni se usa una llave para
autenticarse. Los mensajes de error/estado NO incluyen contenido de la llave.
"""

import base64
import datetime as _dt
import hashlib
import struct
from typing import Any, Dict, List, Optional

try:  # la ausencia de la biblioteca debe poder informarse, no tumbar el módulo
    import cryptography
    from cryptography import x509
    from cryptography.exceptions import UnsupportedAlgorithm
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa, x448, x25519
    from cryptography.hazmat.primitives.serialization import pkcs12, ssh
    CRYPTO_AVAILABLE = True
    CRYPTO_VERSION = getattr(cryptography, '__version__', 'desconocida')
except Exception:  # noqa: BLE001
    CRYPTO_AVAILABLE = False
    CRYPTO_VERSION = None

# ── Estados ───────────────────────────────────────────────────────────────────
S_COMPLETED = 'completed'
S_WEAK = 'completed_with_weaknesses'
S_PARTIAL = 'partial'
S_NEEDS_PASSWORD = 'needs_password'
S_UNSUPPORTED_FORMAT = 'unsupported_format'
S_UNSUPPORTED_ALGORITHM = 'unsupported_algorithm'
S_INVALID = 'invalid'
S_TOOL_UNAVAILABLE = 'tool_unavailable'
S_ERROR = 'error'

# ── Etiquetas PEM conocidas: etiqueta -> (tipo de material, algoritmo, codificación) ──
_PEM_LABELS = {
    'RSA PRIVATE KEY':       ('private_key', 'RSA', 'PKCS#1'),
    'DSA PRIVATE KEY':       ('private_key', 'DSA', 'OpenSSL tradicional'),
    'EC PRIVATE KEY':        ('private_key', 'EC', 'SEC1'),
    'PRIVATE KEY':           ('private_key', None, 'PKCS#8'),
    'ENCRYPTED PRIVATE KEY': ('encrypted_private_key', None, 'PKCS#8 cifrado'),
    'OPENSSH PRIVATE KEY':   ('private_key', None, 'OpenSSH'),
    'PUBLIC KEY':            ('public_key', None, 'SubjectPublicKeyInfo'),
    'RSA PUBLIC KEY':        ('public_key', 'RSA', 'PKCS#1'),
    'CERTIFICATE':           ('certificate', None, 'X.509'),
    'X509 CERTIFICATE':      ('certificate', None, 'X.509'),
}
# Etiquetas que SÍ son material criptográfico pero que este módulo no sabe analizar
_OTHER_LABELS = {
    'CERTIFICATE REQUEST', 'NEW CERTIFICATE REQUEST', 'X509 CRL', 'DH PARAMETERS', 'EC PARAMETERS',
    'PGP PRIVATE KEY BLOCK', 'PGP PUBLIC KEY BLOCK', 'PGP MESSAGE', 'PKCS7', 'CMS', 'TRUSTED CERTIFICATE',
    'ENCRYPTED PRIVATE KEY BLOCK', 'SSH2 PUBLIC KEY', 'SSH2 ENCRYPTED PRIVATE KEY',
}


def label_is_crypto(label: str) -> bool:
    return label in _PEM_LABELS or label in _OTHER_LABELS


def _hex(n: int) -> str:
    h = format(n, 'x')
    return h if len(h) % 2 == 0 else '0' + h


def _hex_bytes(b: bytes) -> str:
    return b.hex()


def _result(**kw) -> Dict[str, Any]:
    base = {
        'material_type': 'invalid', 'algorithm': None, 'key_size': None, 'curve': None,
        'format': None, 'encoding': None, 'protection': 'n/a', 'cipher': None,
        'status': S_ERROR, 'detail_code': None, 'fingerprint': None, 'cert': None,
        'container': None, 'tools': [],
    }
    base.update(kw)
    return base


def _tool(operation: str, result: str, error: Optional[str] = None, alternative: Optional[str] = None) -> Dict[str, Any]:
    return {'tool': 'cryptography', 'version': CRYPTO_VERSION, 'operation': operation,
            'result': result, 'error': error, 'alternative': alternative}


def _spki_fingerprint(pub) -> Optional[str]:
    try:
        der = pub.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        return hashlib.sha256(der).hexdigest()
    except Exception:  # noqa: BLE001
        return None


def _algo_info(key) -> Dict[str, Any]:
    """Algoritmo, tamaño y curva de una llave (privada o pública) ya cargada."""
    if isinstance(key, (rsa.RSAPrivateKey, rsa.RSAPublicKey)):
        return {'algorithm': 'RSA', 'key_size': key.key_size, 'curve': None}
    if isinstance(key, (dsa.DSAPrivateKey, dsa.DSAPublicKey)):
        return {'algorithm': 'DSA', 'key_size': key.key_size, 'curve': None}
    if isinstance(key, (ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey)):
        return {'algorithm': 'EC', 'key_size': key.curve.key_size, 'curve': key.curve.name}
    if isinstance(key, (ed25519.Ed25519PrivateKey, ed25519.Ed25519PublicKey)):
        return {'algorithm': 'Ed25519', 'key_size': 256, 'curve': None}
    if isinstance(key, (ed448.Ed448PrivateKey, ed448.Ed448PublicKey)):
        return {'algorithm': 'Ed448', 'key_size': 456, 'curve': None}
    if isinstance(key, (x25519.X25519PrivateKey, x25519.X25519PublicKey)):
        return {'algorithm': 'X25519', 'key_size': 256, 'curve': None}
    if isinstance(key, (x448.X448PrivateKey, x448.X448PublicKey)):
        return {'algorithm': 'X448', 'key_size': 448, 'curve': None}
    return {'algorithm': None, 'key_size': None, 'curve': None}


def _param(name: str, kind: str, value) -> Dict[str, Any]:
    """Un parámetro. `kind`: 'public' | 'private'. Enteros -> hex; bytes -> hex."""
    if isinstance(value, int):
        return {'name': name, 'kind': kind, 'encoding': 'integer', 'hex': _hex(value), 'bits': value.bit_length()}
    return {'name': name, 'kind': kind, 'encoding': 'bytes', 'hex': _hex_bytes(value), 'bits': len(value) * 8}


def public_params(key) -> List[Dict[str, Any]]:
    """Parámetros públicos de una llave (privada o pública)."""
    pub = key.public_key() if hasattr(key, 'public_key') else key
    if isinstance(pub, rsa.RSAPublicKey):
        n = pub.public_numbers()
        return [_param('n', 'public', n.n), _param('e', 'public', n.e)]
    if isinstance(pub, dsa.DSAPublicKey):
        n = pub.public_numbers()
        pn = n.parameter_numbers
        return [_param('p', 'public', pn.p), _param('q', 'public', pn.q),
                _param('g', 'public', pn.g), _param('y', 'public', n.y)]
    if isinstance(pub, ec.EllipticCurvePublicKey):
        n = pub.public_numbers()
        return [_param('x', 'public', n.x), _param('y', 'public', n.y)]
    if isinstance(pub, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey, x25519.X25519PublicKey, x448.X448PublicKey)):
        return [_param('public_bytes', 'public',
                       pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw))]
    return []


def private_params(key) -> List[Dict[str, Any]]:
    """Parámetros PRIVADOS (solo se piden bajo acción explícita del usuario)."""
    if isinstance(key, rsa.RSAPrivateKey):
        n = key.private_numbers()
        return [_param('d', 'private', n.d), _param('p', 'private', n.p), _param('q', 'private', n.q),
                _param('dP', 'private', n.dmp1), _param('dQ', 'private', n.dmq1), _param('qInv', 'private', n.iqmp)]
    if isinstance(key, dsa.DSAPrivateKey):
        return [_param('x', 'private', key.private_numbers().x)]
    if isinstance(key, ec.EllipticCurvePrivateKey):
        return [_param('d', 'private', key.private_numbers().private_value)]
    if isinstance(key, (ed25519.Ed25519PrivateKey, ed448.Ed448PrivateKey, x25519.X25519PrivateKey, x448.X448PrivateKey)):
        return [_param('private_bytes', 'private',
                       key.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                                         serialization.NoEncryption()))]
    return []


# ── Certificados ──────────────────────────────────────────────────────────────

def _cert_summary(cert) -> Dict[str, Any]:
    now = _dt.datetime.now(_dt.timezone.utc)
    nb, na = cert.not_valid_before_utc, cert.not_valid_after_utc
    try:
        sig_hash = cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else None
    except Exception:  # noqa: BLE001  (Ed25519/Ed448 no usan hash separado)
        sig_hash = None
    try:
        sig_algo = cert.signature_algorithm_oid._name or cert.signature_algorithm_oid.dotted_string
    except Exception:  # noqa: BLE001
        sig_algo = None
    dns: List[str] = []
    exts: List[Dict[str, Any]] = []
    is_ca = None
    for ext in cert.extensions:
        name = getattr(ext.oid, '_name', None) or ext.oid.dotted_string
        exts.append({'name': name, 'critical': ext.critical})
        if isinstance(ext.value, x509.SubjectAlternativeName):
            dns = list(ext.value.get_values_for_type(x509.DNSName))
        if isinstance(ext.value, x509.BasicConstraints):
            is_ca = ext.value.ca
    return {
        'subject': cert.subject.rfc4514_string(),
        'issuer': cert.issuer.rfc4514_string(),
        'serial_hex': _hex(cert.serial_number),
        'not_before': nb.isoformat(),
        'not_after': na.isoformat(),
        'expired': na < now,
        'not_yet_valid': nb > now,
        'days_to_expiry': (na - now).days,
        'signature_algorithm': sig_algo,
        'signature_hash': sig_hash,
        'dns_names': dns,
        'extensions': exts,
        'is_ca': is_ca,
        'self_signed': cert.issuer == cert.subject,
        # Comprobaciones distintas e independientes (no se asume ninguna):
        'checks': {
            'structure_valid': True,                       # se pudo decodificar
            'validity_period': 'expired' if na < now else ('not_yet_valid' if nb > now else 'valid'),
            'chain_trust': 'not_evaluated',                # no se consulta ningún almacén de confianza
            'private_key_match': 'not_evaluated',          # lo calcula el scanner entre archivos del mismo análisis
        },
    }


# ── OpenSSH ───────────────────────────────────────────────────────────────────

def _openssh_cipher(block: bytes) -> Optional[str]:
    """Nombre del cifrado de una llave privada OpenSSH ('none' si no está protegida)."""
    try:
        body = b''.join(line for line in block.splitlines() if line and not line.startswith(b'-----'))
        raw = base64.b64decode(body, validate=False)
        magic = b'openssh-key-v1\x00'
        if not raw.startswith(magic):
            return None
        off = len(magic)
        (ln,) = struct.unpack('>I', raw[off:off + 4])
        return raw[off + 4:off + 4 + ln].decode('ascii', 'replace')
    except Exception:  # noqa: BLE001
        return None


def _legacy_pem_cipher(block: bytes) -> Optional[str]:
    for line in block.splitlines():
        if line.startswith(b'DEK-Info:'):
            return line.split(b':', 1)[1].split(b',')[0].strip().decode('ascii', 'replace')
    return None


def _is_legacy_encrypted(block: bytes) -> bool:
    return b'Proc-Type: 4,ENCRYPTED' in block or b'Proc-Type:4,ENCRYPTED' in block


# ── Carga con clasificación de errores ────────────────────────────────────────

def _load_private(raw: bytes, fmt: str, label: Optional[str], password: Optional[bytes]):
    if label == 'OPENSSH PRIVATE KEY':
        return ssh.load_ssh_private_key(raw, password=password)
    if fmt == 'DER':
        return serialization.load_der_private_key(raw, password=password)
    return serialization.load_pem_private_key(raw, password=password)


def _classify_private_error(exc: Exception, declared_encrypted: bool, had_password: bool) -> Dict[str, Any]:
    msg = str(exc)
    if isinstance(exc, UnsupportedAlgorithm):
        return {'status': S_UNSUPPORTED_ALGORITHM, 'detail_code': 'unsupported_algorithm'}
    if isinstance(exc, TypeError) and 'assword' in msg:
        return {'status': S_NEEDS_PASSWORD, 'detail_code': 'password_required'}
    if declared_encrypted and had_password and isinstance(exc, ValueError):
        # cryptography no distingue siempre "contraseña errónea" de "datos corruptos" en llaves cifradas
        return {'status': S_NEEDS_PASSWORD, 'detail_code': 'wrong_password'}
    if declared_encrypted and isinstance(exc, ValueError) and 'assword' in msg:
        return {'status': S_NEEDS_PASSWORD, 'detail_code': 'password_required'}
    return {'status': S_INVALID, 'detail_code': 'corrupt_or_unsupported'}


# ── Análisis ──────────────────────────────────────────────────────────────────

def analyze(raw: bytes, fmt: str, label: Optional[str] = None,
            password: Optional[bytes] = None, with_params: bool = False) -> Dict[str, Any]:
    """
    Analiza UN bloque de material criptográfico.

    Args:
        raw:   bytes del bloque (PEM completo o DER).
        fmt:   'PEM' | 'DER' | 'OPENSSH_PUB'.
        label: etiqueta PEM (p. ej. 'RSA PRIVATE KEY') si se conoce.
        password: contraseña ENTREGADA por el usuario (nunca se prueban contraseñas).
        with_params: si True, devuelve `public_params` y `private_params` (solo bajo acción explícita).

    Nunca lanza: siempre devuelve un dict con `status`.
    """
    if not CRYPTO_AVAILABLE:
        return _result(status=S_TOOL_UNAVAILABLE, detail_code='cryptography_missing', format=fmt,
                       tools=[{'tool': 'cryptography', 'version': None, 'operation': 'import',
                               'result': 'unavailable', 'error': 'biblioteca no instalada', 'alternative': None}])
    try:
        if fmt == 'OPENSSH_PUB':
            return _analyze_openssh_public(raw, with_params)
        if fmt == 'PEM':
            return _analyze_pem(raw, label, password, with_params)
        if fmt == 'DER':
            return _analyze_der(raw, password, with_params)
        return _result(status=S_UNSUPPORTED_FORMAT, detail_code='unknown_format', format=fmt)
    except Exception as exc:  # noqa: BLE001 -- jamás debe tumbar el escaneo; sin contenido de la llave en el mensaje
        return _result(status=S_ERROR, detail_code='analysis_error', format=fmt,
                       tools=[_tool('analyze', 'error', error=type(exc).__name__)])


def _analyze_pem(raw: bytes, label: Optional[str], password: Optional[bytes], with_params: bool) -> Dict[str, Any]:
    if label in _OTHER_LABELS or label not in _PEM_LABELS:
        return _result(material_type='other', format='PEM', encoding=label, status=S_UNSUPPORTED_FORMAT,
                       detail_code='unsupported_label',
                       tools=[_tool('classify', 'unsupported', error=f'etiqueta PEM no soportada: {label}')])
    mtype, algo, encoding = _PEM_LABELS[label]
    if mtype in ('private_key', 'encrypted_private_key'):
        return _analyze_private(raw, 'PEM', label, mtype, algo, encoding, password, with_params)
    try:
        if mtype == 'public_key':
            pub = serialization.load_pem_public_key(raw)
        else:
            cert = x509.load_pem_x509_certificate(raw)
    except UnsupportedAlgorithm as exc:
        return _result(material_type=mtype, format='PEM', encoding=encoding, status=S_UNSUPPORTED_ALGORITHM,
                       detail_code='unsupported_algorithm',
                       tools=[_tool('load', 'unsupported', error=type(exc).__name__)])
    except (ValueError, TypeError) as exc:
        return _result(material_type=mtype, format='PEM', encoding=encoding, status=S_INVALID,
                       detail_code='corrupt_or_unsupported',
                       tools=[_tool('load', 'invalid', error=type(exc).__name__)])
    if mtype == 'public_key':
        return _finish_public(pub, 'PEM', encoding, with_params)
    return _finish_cert(cert, 'PEM', encoding)


def _analyze_private(raw, fmt, label, mtype, algo_hint, encoding, password, with_params):
    cipher = None
    declared_encrypted = mtype == 'encrypted_private_key'
    if fmt == 'PEM' and _is_legacy_encrypted(raw):
        declared_encrypted, cipher = True, _legacy_pem_cipher(raw)
    if label == 'OPENSSH PRIVATE KEY':
        c = _openssh_cipher(raw)
        if c and c != 'none':
            declared_encrypted, cipher = True, c
    protection = 'encrypted' if declared_encrypted else 'none'
    base = dict(material_type='encrypted_private_key' if declared_encrypted else 'private_key',
                algorithm=algo_hint, format=fmt, encoding=encoding, protection=protection, cipher=cipher)
    try:
        key = _load_private(raw, fmt, label, password if declared_encrypted else None)
    except Exception as exc:  # noqa: BLE001
        cls = _classify_private_error(exc, declared_encrypted, password is not None)
        return _result(**base, **cls, tools=[_tool('load_private_key', cls['status'], error=type(exc).__name__)])
    info = _algo_info(key)
    out = _result(**{**base, 'algorithm': info['algorithm'] or algo_hint}, key_size=info['key_size'],
                  curve=info['curve'], status=S_COMPLETED, fingerprint=_spki_fingerprint(key.public_key()),
                  tools=[_tool('load_private_key', 'ok')])
    if declared_encrypted:
        out['detail_code'] = 'decrypted_with_user_password'   # solo si el usuario entregó la contraseña
    if with_params:
        out['public_params'] = public_params(key)
        out['private_params'] = private_params(key)
        out['tools'].append(_tool('extract_parameters', 'ok'))
    return out


def _finish_public(pub, fmt, encoding, with_params):
    info = _algo_info(pub)
    out = _result(material_type='public_key', format=fmt, encoding=encoding, protection='n/a',
                  status=S_COMPLETED if info['algorithm'] else S_UNSUPPORTED_ALGORITHM,
                  fingerprint=_spki_fingerprint(pub), tools=[_tool('load_public_key', 'ok')], **info)
    if with_params:
        out['public_params'] = public_params(pub)
        out['private_params'] = []
    return out


def _finish_cert(cert, fmt, encoding):
    pub = cert.public_key()
    info = _algo_info(pub)
    return _result(material_type='certificate', format=fmt, encoding=encoding, protection='n/a',
                   status=S_COMPLETED, fingerprint=_spki_fingerprint(pub), cert=_cert_summary(cert),
                   tools=[_tool('load_certificate', 'ok')], **info)


def _analyze_openssh_public(raw: bytes, with_params: bool) -> Dict[str, Any]:
    pub = ssh.load_ssh_public_key(raw)
    return _finish_public(pub, 'OpenSSH', 'OpenSSH', with_params)


def _der_looks_pkcs12(raw: bytes) -> bool:
    # PFX: SEQUENCE { INTEGER 3, SEQUENCE { OID pkcs7-data ... } }
    return raw[:2] != b'' and b'\x02\x01\x03' in raw[:12] and b'\x2a\x86\x48\x86\xf7\x0d\x01\x07' in raw[:48]


def _analyze_der(raw: bytes, password: Optional[bytes], with_params: bool) -> Dict[str, Any]:
    for loader, kind in ((x509.load_der_x509_certificate, 'cert'), (serialization.load_der_public_key, 'pub')):
        try:
            obj = loader(raw)
        except Exception:  # noqa: BLE001
            continue
        return _finish_cert(obj, 'DER', 'X.509') if kind == 'cert' else _finish_public(obj, 'DER', 'SubjectPublicKeyInfo', with_params)

    if _der_looks_pkcs12(raw):
        return _analyze_pkcs12(raw, password, with_params)

    try:
        key = serialization.load_der_private_key(raw, password=None)
    except TypeError:
        if password is None:
            return _result(material_type='encrypted_private_key', format='DER', encoding='PKCS#8 cifrado',
                           protection='encrypted', status=S_NEEDS_PASSWORD, detail_code='password_required',
                           tools=[_tool('load_private_key', 'needs_password')])
        try:
            key = serialization.load_der_private_key(raw, password=password)
        except Exception as exc:  # noqa: BLE001
            cls = _classify_private_error(exc, True, True)
            return _result(material_type='encrypted_private_key', format='DER', encoding='PKCS#8 cifrado',
                           protection='encrypted', **cls, tools=[_tool('load_private_key', cls['status'], error=type(exc).__name__)])
        return _private_ok(key, 'DER', 'PKCS#8 cifrado', True, with_params)
    except UnsupportedAlgorithm:
        return _result(format='DER', status=S_UNSUPPORTED_ALGORITHM, detail_code='unsupported_algorithm',
                       tools=[_tool('load_private_key', 'unsupported')])
    except Exception:  # noqa: BLE001
        return _result(format='DER', status=S_INVALID, detail_code='corrupt_or_unsupported',
                       tools=[_tool('decode_der', 'invalid')])
    return _private_ok(key, 'DER', 'PKCS#8/PKCS#1/SEC1 (DER)', False, with_params)


def _private_ok(key, fmt, encoding, was_encrypted, with_params):
    info = _algo_info(key)
    out = _result(material_type='encrypted_private_key' if was_encrypted else 'private_key', format=fmt,
                  encoding=encoding, protection='encrypted' if was_encrypted else 'none',
                  status=S_COMPLETED, fingerprint=_spki_fingerprint(key.public_key()),
                  detail_code='decrypted_with_user_password' if was_encrypted else None,
                  tools=[_tool('load_private_key', 'ok')], **info)
    if with_params:
        out['public_params'] = public_params(key)
        out['private_params'] = private_params(key)
    return out


def _analyze_pkcs12(raw: bytes, password: Optional[bytes], with_params: bool = False) -> Dict[str, Any]:
    """Contenedor PKCS#12: casi siempre protegido con contraseña. No se prueban contraseñas."""
    base = dict(material_type='pkcs12', format='DER', encoding='PKCS#12', protection='password-container')
    try:
        key, cert, extra = pkcs12.load_key_and_certificates(raw, password)
    except Exception as exc:  # noqa: BLE001
        return _result(**base, status=S_NEEDS_PASSWORD,
                       detail_code='wrong_password' if password is not None else 'password_required',
                       tools=[_tool('load_pkcs12', 'needs_password', error=type(exc).__name__)])
    parts = {'has_private_key': key is not None, 'certificates': (1 if cert is not None else 0) + len(extra or [])}
    info = _algo_info(key) if key is not None else (_algo_info(cert.public_key()) if cert is not None else {})
    out = _result(**base, **info, status=S_COMPLETED,
                  detail_code='decrypted_with_user_password' if password is not None else None,
                  container=parts,
                  fingerprint=_spki_fingerprint(key.public_key()) if key is not None else None,
                  cert=_cert_summary(cert) if cert is not None else None,
                  tools=[_tool('load_pkcs12', 'ok')])
    if with_params and key is not None:
        out['public_params'] = public_params(key)
        out['private_params'] = private_params(key)
    return out
