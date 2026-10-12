"""
OpenSSL como herramienta de CONTRASTE (no es el método principal).

Solo se invoca de verdad cuando el binario existe; si no, se informa
"no disponible" y se conserva el resultado de `cryptography`. El contenido de
la llave se pasa por stdin (sin archivos temporales) y NUNCA se registran la
salida ni el stderr de OpenSSH/OpenSSL.
"""

import hashlib
import shutil
import subprocess
from typing import Any, Dict, Optional

_TIMEOUT = 10
_version_cache: Optional[str] = None
_checked = False


def binary() -> Optional[str]:
    return shutil.which('openssl')


def version() -> Optional[str]:
    global _version_cache, _checked
    if _checked:
        return _version_cache
    _checked = True
    exe = binary()
    if exe:
        try:
            out = subprocess.run([exe, 'version'], capture_output=True, timeout=_TIMEOUT, check=False)
            _version_cache = out.stdout.decode('ascii', 'replace').strip() or None
        except (OSError, subprocess.SubprocessError):
            _version_cache = None
    return _version_cache


def _tool(operation: str, result: str, error: Optional[str] = None, alternative: Optional[str] = None) -> Dict[str, Any]:
    return {'tool': 'openssl', 'version': version(), 'operation': operation,
            'result': result, 'error': error, 'alternative': alternative}


def _run(args, data: bytes) -> Optional[bytes]:
    exe = binary()
    try:
        p = subprocess.run([exe, *args], input=data, capture_output=True, timeout=_TIMEOUT, check=False)
    except (OSError, subprocess.SubprocessError):
        return None
    return p.stdout if p.returncode == 0 and p.stdout else None


def _spki_hash_from_pem_pub(pem_pub: bytes) -> Optional[str]:
    try:
        from cryptography.hazmat.primitives import serialization
        pub = serialization.load_pem_public_key(pem_pub)
        der = pub.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        return hashlib.sha256(der).hexdigest()
    except Exception:  # noqa: BLE001
        return None


def cross_check(raw: bytes, fmt: str, label: Optional[str], material_type: str,
                expected_fingerprint: Optional[str]) -> Dict[str, Any]:
    """
    Pide a OpenSSL que derive la llave pública y compara su huella SHA-256 (SPKI) con la que
    obtuvo `cryptography`. Devuelve una entrada para `tools[]` del hallazgo.
    """
    op = 'derive_public_key'
    if binary() is None:
        return _tool(op, 'unavailable', error='openssl no está instalado en el servidor',
                     alternative='se usó solo la biblioteca cryptography')
    if fmt == 'OPENSSH_PUB' or label == 'OPENSSH PRIVATE KEY':
        return _tool(op, 'skipped', error='OpenSSL no lee el formato OpenSSH', alternative='cryptography')
    if material_type not in ('private_key', 'public_key', 'certificate') or not expected_fingerprint:
        return _tool(op, 'skipped', error='no aplica a este tipo de material o no se pudo leer sin contraseña')

    inform = ['-inform', 'DER'] if fmt == 'DER' else []
    if material_type == 'certificate':
        out = _run(['x509', '-noout', '-pubkey', *inform], raw)
    elif material_type == 'public_key':
        out = _run(['pkey', '-pubin', '-pubout', *inform], raw)
    else:
        out = _run(['pkey', '-pubout', *inform], raw)
    if out is None:
        return _tool(op, 'error', error='OpenSSL no pudo leer el material', alternative='cryptography')
    got = _spki_hash_from_pem_pub(out)
    if got is None:
        return _tool(op, 'error', error='la salida de OpenSSL no se pudo interpretar')
    if got == expected_fingerprint:
        return _tool(op, 'match')
    return _tool(op, 'mismatch', error='la huella de la llave pública difiere entre OpenSSL y cryptography')
