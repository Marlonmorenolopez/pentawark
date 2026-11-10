"""
CryptoKeyScanner — séptima herramienta de Code Scan: detecta, identifica y analiza
material criptográfico (llaves y certificados) dentro del árbol de archivos.

Contrato igual al de los demás scanners: `scan(root_path) -> dict` con
`findings`, `error`, `status`. Además devuelve:
  - `items`:   una tarjeta por archivo/bloque criptográfico (SOLO metadatos públicos).
  - `_blobs`:  {item_id: bytes} con el material crudo. **Es transitorio**: app.py lo
               mueve a la custodia temporal (vault) y lo elimina del resultado ANTES
               de persistirlo. Nunca debe llegar al historial ni a los logs.
"""

import logging
import time
from typing import Any, Dict, List

from modules.code_security.crypto_inspector import analyze as _an
from modules.code_security.crypto_inspector import detect as _det
from modules.code_security.crypto_inspector import openssl_ref as _ossl
from modules.code_security.crypto_inspector import risk as _risk

logger = logging.getLogger(__name__)

_MAX_OPENSSL_CROSSCHECKS = 100


def _name(path: str) -> str:
    return path.rsplit('/', 1)[-1]


class CryptoKeyScanner:
    name = 'crypto_keys'

    def __init__(self, locale: str = 'es'):
        self.locale = locale

    @property
    def available(self) -> bool:
        return _an.CRYPTO_AVAILABLE

    def scan(self, root_path: str) -> Dict[str, Any]:
        started = time.monotonic()
        if not _an.CRYPTO_AVAILABLE:
            return {'findings': [], 'items': [], 'error': 'La biblioteca "cryptography" no está instalada en el servidor',
                    'status': 'skipped', 'warning': None, 'tools': self._tools_used(), '_blobs': {}}

        candidates, stats = _det.walk_candidates(root_path)
        items: List[Dict[str, Any]] = []
        blobs: Dict[str, bytes] = {}
        crosschecks = 0

        for cand in candidates:
            res = _an.analyze(cand.raw, cand.fmt, cand.label)
            tools = list(res.pop('tools'))
            if crosschecks < _MAX_OPENSSL_CROSSCHECKS and res['status'] == _an.S_COMPLETED:
                tools.append(_ossl.cross_check(cand.raw, cand.fmt, cand.label, res['material_type'], res['fingerprint']))
                crosschecks += 1
            item = {
                'id': cand.item_id, 'source_format': cand.fmt, 'pem_label': cand.label, 'file': cand.rel_path, 'name': _name(cand.rel_path), 'line': cand.line,
                'context': _risk.path_context(cand.rel_path), 'tools': tools, 'matches': [],
                'inspectable': False, **res,
            }
            item['weaknesses'] = _risk.assess(item, cand.rel_path, self.locale)
            item['risk'] = _risk.max_severity(item['weaknesses'])
            if item['status'] == _an.S_COMPLETED and any(w['kind'] == 'weakness' for w in item['weaknesses']):
                item['status'] = _an.S_WEAK
            # Marca explícita: lo que el análisis estático NO puede afirmar
            item['assessment'] = {'confirmed_exposure': None, 'active_use': None}
            items.append(item)
            blobs[item['id']] = cand.raw

        self._link_certs_to_keys(items)
        findings = self._to_findings(items)
        warning = self._warning(stats)
        return {
            'findings': findings, 'items': items, 'error': None, 'status': 'completed', 'warning': warning,
            'files_visited': stats['files_visited'], 'files_read': stats['files_read'],
            'truncated': stats['truncated'], 'tools': self._tools_used(),
            'duration_s': round(time.monotonic() - started, 1),
            'limitations': _risk.LIMITATIONS[self.locale if self.locale in _risk.LIMITATIONS else 'es'],
            '_blobs': blobs,
        }

    @staticmethod
    def _tools_used() -> List[Dict[str, Any]]:
        return [
            {'tool': 'cryptography', 'version': _an.CRYPTO_VERSION, 'role': 'primary', 'available': _an.CRYPTO_AVAILABLE},
            {'tool': 'openssl', 'version': _ossl.version(), 'role': 'cross-check', 'available': _ossl.binary() is not None},
        ]

    @staticmethod
    def _link_certs_to_keys(items: List[Dict[str, Any]]) -> None:
        """Correspondencia certificado <-> llave privada por huella de la llave pública (mismo análisis)."""
        by_fp: Dict[str, List[Dict[str, Any]]] = {}
        for it in items:
            if it.get('fingerprint'):
                by_fp.setdefault(it['fingerprint'], []).append(it)
        for group in by_fp.values():
            privs = [i for i in group if i['material_type'] in ('private_key', 'encrypted_private_key')]
            certs = [i for i in group if i['material_type'] == 'certificate']
            for c in certs:
                if c.get('cert') is not None:
                    c['cert']['checks']['private_key_match'] = 'match' if privs else 'no_private_key_found'
                c['matches'] = [p['id'] for p in privs]
            for p in privs:
                p['matches'] = [c['id'] for c in certs]

    @staticmethod
    def _to_findings(items: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Un hallazgo por debilidad/exposición (alimenta resumen y score). SIN material de la llave."""
        out = []
        for it in items:
            for w in it['weaknesses']:
                out.append({
                    'file': it['file'], 'line': it['line'], 'rule_id': w['code'], 'rule': w['title'],
                    'type': w['kind'], 'severity': w['severity'], 'description': w['description'],
                    'algorithm': it.get('algorithm'), 'key_size': it.get('key_size'), 'item_id': it['id'],
                })
        return out

    @staticmethod
    def _warning(stats: Dict[str, Any]) -> Any:
        t = stats.get('truncated')
        if t == 'candidates':
            return f'Se alcanzó el límite de {_det.MAX_CANDIDATES} elementos criptográficos: hay más sin listar.'
        if t == 'files':
            return f'Se alcanzó el límite de {_det.MAX_FILES_VISITED} archivos revisados: el análisis es parcial.'
        if t == 'time':
            return f'Se alcanzó el límite de {_det.MAX_SECONDS} s de recorrido: el análisis es parcial.'
        return None
