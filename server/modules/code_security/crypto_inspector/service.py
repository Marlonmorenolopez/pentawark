"""
Lógica de las rutas de inspección/exportación, SIN Flask (para poder probarla aislada).
app.py solo valida la petición HTTP, llama a estas funciones y arma la respuesta.

Regla de oro: ningún valor privado ni contraseña se registra, y los errores devuelven
códigos, nunca contenido de llaves.
"""

from typing import Any, Dict, List, Optional, Tuple

from modules.code_security.crypto_inspector import analyze as _an

MAX_PASSWORD_LEN = 256


def private_gate(api_token_configured: bool, allow_without_token: bool, vault_enabled: bool) -> Optional[Tuple[int, str]]:
    """
    Operaciones que pueden entregar parámetros PRIVADOS. Devuelve (http_status, code) si hay que
    rechazar, o None si se puede continuar. Sin API_TOKEN configurado se rechaza (cualquiera en la
    red podría pedir llaves) salvo excepción explícita de laboratorio.
    """
    if not api_token_configured and not allow_without_token:
        return 403, 'token_required'
    if not vault_enabled:
        return 503, 'vault_disabled'
    return None


def parse_password(value: Any) -> Tuple[Optional[bytes], bool]:
    """(bytes|None, inválida). La contraseña la entrega el usuario; solo se usa en memoria."""
    if value is None or value == '':
        return None, False
    if not isinstance(value, str) or len(value) > MAX_PASSWORD_LEN:
        return None, True
    return value.encode('utf-8'), False


def find_item(scan: Dict[str, Any], item_id: str) -> Optional[Dict[str, Any]]:
    return next((i for i in (scan.get('crypto_keys') or {}).get('items', []) if i.get('id') == item_id), None)


def inspect_item(vault, scan_id: str, item: Dict[str, Any], password: Optional[bytes]) -> Tuple[int, Dict[str, Any]]:
    """Inspección completa de UN elemento. Devuelve (http_status, payload)."""
    blob = vault.get(scan_id, item['id'])
    if blob is None:
        return 410, {'code': 'expired'}
    res = _an.analyze(blob, item.get('source_format') or 'PEM', item.get('pem_label'),
                      password=password, with_params=True)
    return 200, {
        'item_id': item['id'], 'status': res['status'], 'detail_code': res.get('detail_code'),
        'material_type': res['material_type'], 'algorithm': res.get('algorithm'),
        'key_size': res.get('key_size'), 'curve': res.get('curve'), 'protection': res.get('protection'),
        'public_params': res.get('public_params', []), 'private_params': res.get('private_params', []),
        'tools': res.get('tools', []),
    }


def collect_full_params(vault, scan_id: str, scan: Dict[str, Any], wanted: Optional[List[str]],
                        passwords: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    """
    Parámetros recuperados de forma fiable para la exportación completa. Solo entran los elementos
    que se pudieron leer; las contraseñas se usan en memoria y NO se incluyen en el resultado.
    """
    out: Dict[str, Dict[str, Any]] = {}
    for it in (scan.get('crypto_keys') or {}).get('items', []):
        iid = it.get('id')
        if (wanted is not None and iid not in wanted) or not it.get('inspectable'):
            continue
        blob = vault.get(scan_id, iid)
        if blob is None:
            continue
        pw, bad = parse_password(passwords.get(iid))
        if bad:
            continue
        res = _an.analyze(blob, it.get('source_format') or 'PEM', it.get('pem_label'), password=pw, with_params=True)
        out[iid] = {'status': res['status'], 'public_params': res.get('public_params', []),
                    'private_params': res.get('private_params', [])}
    return out
