"""
Enmascarado de secretos para Gitleaks y TruffleHog.

Antes: primeros 4 + un '*' POR CADA carácter + últimos 4. Una llave privada de
1.700 caracteres producía 1.700 asteriscos que rompían el recuadro de la UI.
Ahora la máscara tiene largo acotado y, para llaves privadas, muestra el tipo
de llave y el tamaño en vez de basura.

Por seguridad el valor completo NO se guarda por defecto (el reporte y el
historial quedarían con credenciales vivas en claro). Para laboratorio/pentest
autorizado se puede activar con CODE_SCAN_REVEAL_SECRETS=true.
"""

import os
import re

_MAX_STARS = 12
_PEM_RE = re.compile(r'-----BEGIN ([A-Z0-9 ]+?)-----')


def reveal_enabled() -> bool:
    return os.environ.get('CODE_SCAN_REVEAL_SECRETS', 'false').strip().lower() in ('1', 'true', 'yes')


def mask_secret(secret: str) -> str:
    secret = secret or ''
    if reveal_enabled():
        return secret
    m = _PEM_RE.match(secret.strip())
    if m:
        return f'-----BEGIN {m.group(1)}----- … ({len(secret)} caracteres, contenido oculto)'
    if len(secret) <= 8:
        return '*' * len(secret)
    return f'{secret[:4]}{"*" * min(len(secret) - 8, _MAX_STARS)}{secret[-4:]}'
