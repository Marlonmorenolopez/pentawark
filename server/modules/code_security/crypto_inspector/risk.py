"""
Evaluación de riesgos criptográficos con criterios verificables.

Se distinguen cuatro cosas que NO deben mezclarse:
  1. Debilidad criptográfica   (p. ej. RSA de 1024 bits)            -> kind='weakness'
  2. Posible exposición        (llave privada dentro del proyecto)   -> kind='possible_exposure'
  3. Exposición confirmada     (evidencia de acceso no autorizado)   -> NO se puede determinar con
  4. Uso activo confirmado     (evidencia de uso en un servicio)        análisis estático: queda 'no evaluado'.

Encontrar una llave en un repositorio NO prueba que esté comprometida, y que una
llave no tenga contraseña NO la vuelve "vulnerable" por sí solo: el contexto
(ruta de prueba, dependencia de terceros) rebaja la severidad.
"""

import re
from typing import Any, Dict, List, Optional

_TEST_RE = re.compile(r'(^|/)(tests?|__tests__|specs?|fixtures?|examples?|samples?|testdata|demo|mocks?)(/|$)|(^|/)[^/]*(test|example|sample)[^/]*$', re.I)
_DEP_RE = re.compile(r'(^|/)(node_modules|vendor|site-packages|bower_components|third_party)(/|$)')

_SEV_ORDER = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1}
_WEAK_HASHES = {'md5', 'sha1'}

# Catálogo de textos (servidor). La UI usa su propio catálogo i18n por `code`.
CATALOG: Dict[str, Dict[str, Dict[str, str]]] = {
    'rsa_key_too_small': {
        'es': {'title': 'Llave RSA de tamaño insuficiente',
               'description': 'La llave RSA tiene {bits} bits. Menos de 2048 bits se considera débil y ya no es aceptable hoy.',
               'recommendation': 'Generar una llave RSA de al menos 2048 bits (preferible 3072) o usar Ed25519/ECDSA P-256, y reemplazar la actual.'},
        'en': {'title': 'RSA key size too small',
               'description': 'The RSA key is {bits} bits. Anything under 2048 bits is considered weak and is no longer acceptable.',
               'recommendation': 'Generate an RSA key of at least 2048 bits (3072 preferred) or use Ed25519/ECDSA P-256, and replace the current one.'},
    },
    'dsa_key_too_small': {
        'es': {'title': 'Llave DSA de tamaño insuficiente',
               'description': 'La llave DSA tiene {bits} bits (se recomienda al menos 2048).',
               'recommendation': 'Migrar a Ed25519 o ECDSA; DSA está en desuso.'},
        'en': {'title': 'DSA key size too small',
               'description': 'The DSA key is {bits} bits (at least 2048 is recommended).',
               'recommendation': 'Migrate to Ed25519 or ECDSA; DSA is deprecated.'},
    },
    'dsa_deprecated': {
        'es': {'title': 'Algoritmo DSA obsoleto',
               'description': 'DSA está en desuso (excluido de las firmas nuevas en FIPS 186-5 y deshabilitado por defecto en OpenSSH).',
               'recommendation': 'Reemplazar por Ed25519 o ECDSA.'},
        'en': {'title': 'Deprecated DSA algorithm',
               'description': 'DSA is deprecated (removed for new signatures in FIPS 186-5 and disabled by default in OpenSSH).',
               'recommendation': 'Replace with Ed25519 or ECDSA.'},
    },
    'ec_curve_weak': {
        'es': {'title': 'Curva elíptica débil',
               'description': 'La curva {curve} ofrece solo {bits} bits; por debajo de 224 bits no se considera segura.',
               'recommendation': 'Usar una curva de al menos 256 bits (P-256, P-384) o Ed25519.'},
        'en': {'title': 'Weak elliptic curve',
               'description': 'Curve {curve} offers only {bits} bits; below 224 bits it is not considered secure.',
               'recommendation': 'Use a curve of at least 256 bits (P-256, P-384) or Ed25519.'},
    },
    'private_key_in_repo': {
        'es': {'title': 'Llave privada sin protección dentro del proyecto',
               'description': 'Hay una llave privada sin cifrar en el árbol de archivos analizado. Esto es una POSIBLE exposición: no prueba que esté comprometida ni que se use en un servicio.',
               'recommendation': 'Si la llave es real, tratarla como comprometida: generar una nueva, revocar la anterior, sacarla del repositorio (gestor de secretos / variables de entorno), añadir *.key y *.pem al .gitignore y limpiar el historial.'},
        'en': {'title': 'Unprotected private key inside the project',
               'description': 'An unencrypted private key exists in the analyzed file tree. This is a POSSIBLE exposure: it does not prove it is compromised or used by any service.',
               'recommendation': 'If the key is real, treat it as compromised: generate a new one, revoke the old one, remove it from the repository (secret manager / environment variables), add *.key and *.pem to .gitignore and clean the history.'},
    },
    'encrypted_key_in_repo': {
        'es': {'title': 'Llave privada cifrada dentro del proyecto',
               'description': 'Hay una llave privada protegida con contraseña en el repositorio. Su seguridad depende de la fortaleza de esa contraseña.',
               'recommendation': 'Sacar la llave del repositorio y guardarla en un gestor de secretos.'},
        'en': {'title': 'Encrypted private key inside the project',
               'description': 'A password-protected private key is in the repository. Its safety depends on the strength of that password.',
               'recommendation': 'Remove the key from the repository and store it in a secret manager.'},
    },
    'pkcs12_in_repo': {
        'es': {'title': 'Contenedor PKCS#12 dentro del proyecto',
               'description': 'Hay un contenedor PKCS#12 (.p12/.pfx) con material privado protegido por contraseña.',
               'recommendation': 'Sacarlo del repositorio y guardarlo en un gestor de secretos.'},
        'en': {'title': 'PKCS#12 container inside the project',
               'description': 'A PKCS#12 container (.p12/.pfx) with password-protected private material is in the repository.',
               'recommendation': 'Remove it from the repository and store it in a secret manager.'},
    },
    'cert_expired': {
        'es': {'title': 'Certificado caducado', 'description': 'El certificado caducó el {not_after}.',
               'recommendation': 'Renovar o retirar el certificado.'},
        'en': {'title': 'Expired certificate', 'description': 'The certificate expired on {not_after}.',
               'recommendation': 'Renew or remove the certificate.'},
    },
    'cert_expiring_soon': {
        'es': {'title': 'Certificado próximo a caducar', 'description': 'El certificado caduca en {days} día(s) ({not_after}).',
               'recommendation': 'Planificar la renovación.'},
        'en': {'title': 'Certificate expiring soon', 'description': 'The certificate expires in {days} day(s) ({not_after}).',
               'recommendation': 'Plan the renewal.'},
    },
    'cert_not_yet_valid': {
        'es': {'title': 'Certificado aún no vigente', 'description': 'El certificado empieza a ser válido el {not_before}.',
               'recommendation': 'Comprobar la fecha del sistema o el certificado emitido.'},
        'en': {'title': 'Certificate not yet valid', 'description': 'The certificate becomes valid on {not_before}.',
               'recommendation': 'Check the system clock or the issued certificate.'},
    },
    'cert_weak_signature': {
        'es': {'title': 'Firma de certificado débil', 'description': 'El certificado está firmado con {hash}, un hash considerado inseguro.',
               'recommendation': 'Reemitir el certificado con SHA-256 o superior.'},
        'en': {'title': 'Weak certificate signature', 'description': 'The certificate is signed with {hash}, a hash considered insecure.',
               'recommendation': 'Reissue the certificate with SHA-256 or stronger.'},
    },
}


def _text(code: str, locale: str, **params) -> Dict[str, str]:
    cat = CATALOG[code].get(locale) or CATALOG[code]['es']
    return {k: v.format(**params) for k, v in cat.items()}


def path_context(rel_path: str) -> str:
    """'dependency' (node_modules, vendor…), 'test' (rutas de prueba) o 'project'."""
    p = rel_path.replace('\\', '/')
    if _DEP_RE.search(p):
        return 'dependency'
    if _TEST_RE.search(p):
        return 'test'
    return 'project'


def _w(code: str, kind: str, severity: str, locale: str = 'es', **params) -> Dict[str, Any]:
    return {'code': code, 'kind': kind, 'severity': severity, 'params': params, **_text(code, locale, **params)}


def assess(item: Dict[str, Any], rel_path: str, locale: str = 'es') -> List[Dict[str, Any]]:
    """Debilidades y posibles exposiciones de UN hallazgo (sin llamadas externas)."""
    out: List[Dict[str, Any]] = []
    if item.get('status') in ('invalid', 'error', 'tool_unavailable', 'unsupported_format'):
        return out  # un fallo de análisis NUNCA se convierte en vulnerabilidad

    algo, bits, mtype = item.get('algorithm'), item.get('key_size'), item.get('material_type')
    context = path_context(rel_path)

    # ── Debilidades de la llave (aplican a llaves privadas, públicas y a la llave de un certificado)
    if algo == 'RSA' and bits:
        if bits < 2048:
            out.append(_w('rsa_key_too_small', 'weakness', 'high' if bits < 1024 else 'medium', locale, bits=bits))
    elif algo == 'DSA':
        out.append(_w('dsa_deprecated', 'weakness', 'low', locale))
        if bits and bits < 2048:
            out.append(_w('dsa_key_too_small', 'weakness', 'high' if bits < 1024 else 'medium', locale, bits=bits))
    elif algo == 'EC' and bits and bits < 224:
        out.append(_w('ec_curve_weak', 'weakness', 'high', locale, curve=item.get('curve') or '?', bits=bits))

    # ── Certificados
    cert = item.get('cert')
    if mtype == 'certificate' and cert:
        if cert['expired']:
            out.append(_w('cert_expired', 'weakness', 'low' if context != 'project' else 'medium', locale, not_after=cert['not_after']))
        elif cert['not_yet_valid']:
            out.append(_w('cert_not_yet_valid', 'weakness', 'low', locale, not_before=cert['not_before']))
        elif cert['days_to_expiry'] <= 30:
            out.append(_w('cert_expiring_soon', 'weakness', 'low', locale, days=cert['days_to_expiry'], not_after=cert['not_after']))
        if (cert.get('signature_hash') or '').lower() in _WEAK_HASHES:
            out.append(_w('cert_weak_signature', 'weakness', 'medium', locale, hash=cert['signature_hash'].upper()))

    # ── Posible exposición (el contexto rebaja la severidad; no se afirma compromiso)
    if mtype == 'private_key':
        sev = 'medium' if context == 'project' else 'low'
        out.append(_w('private_key_in_repo', 'possible_exposure', sev, locale))
    elif mtype == 'encrypted_private_key':
        out.append(_w('encrypted_key_in_repo', 'possible_exposure', 'low', locale))
    elif mtype == 'pkcs12':
        out.append(_w('pkcs12_in_repo', 'possible_exposure', 'low', locale))
    return out


def max_severity(weaknesses: List[Dict[str, Any]]) -> Optional[str]:
    best = None
    for w in weaknesses:
        if best is None or _SEV_ORDER.get(w['severity'], 0) > _SEV_ORDER.get(best, 0):
            best = w['severity']
    return best


def retext(weaknesses: List[Dict[str, Any]], locale: str) -> List[Dict[str, Any]]:
    """Reaplica los textos del catálogo en otro idioma (informes/exportaciones)."""
    out = []
    for w in weaknesses:
        if w.get('code') in CATALOG:
            out.append({**w, **_text(w['code'], locale, **(w.get('params') or {}))})
        else:
            out.append(w)
    return out


LIMITATIONS = {
    'es': [
        'El análisis es estático: no se confirma exposición real ni uso activo del material en un servicio.',
        'Solo se analiza el árbol de archivos actual; las llaves ya borradas del historial de git no se inspeccionan aquí.',
        'No se verifica la cadena de confianza de los certificados ni su instalación en ningún servidor.',
        'Los contenedores y llaves cifradas no se descifran sin la contraseña que entregue el usuario; no se prueban contraseñas.',
    ],
    'en': [
        'The analysis is static: actual exposure or active use of the material in a service is not confirmed.',
        'Only the current file tree is analyzed; keys already removed from git history are not inspected here.',
        'Certificate trust chains and their installation on any server are not verified.',
        'Containers and encrypted keys are not decrypted without a user-supplied password; passwords are never guessed.',
    ],
}
