"""
Exportación de resultados criptográficos.

Dos modalidades claramente separadas:
  A) INFORME TÉCNICO  -> solo metadatos del análisis. NUNCA parámetros privados ni contraseñas.
  B) EXPORTACIÓN COMPLETA -> añade los parámetros privados recuperados de forma fiable. El
     endpoint exige confirmación explícita. El archivo se genera en la respuesta: no se guarda
     en disco ni en el historial. Las contraseñas usadas para abrir llaves NO se incluyen.

Los nombres de archivo los fija el servidor (nada viene del cliente).
"""

import json
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from modules.code_security.crypto_inspector import analyze as _an
from modules.code_security.crypto_inspector import risk as _risk

_FORMATS = ('json', 'txt')
_MODES = ('technical', 'full')


def safe_filename(scan_id: str, mode: str, fmt: str) -> str:
    sid = re.sub(r'[^a-f0-9]', '', (scan_id or '').lower())[:8] or 'scan'
    stamp = datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')
    mode = mode if mode in _MODES else 'technical'
    fmt = fmt if fmt in _FORMATS else 'json'
    return f'crypto-{mode}-{sid}-{stamp}.{fmt}'


def _lang(locale: str) -> str:
    return locale if locale in ('es', 'en') else 'es'


def _item_view(item: Dict[str, Any], locale: str) -> Dict[str, Any]:
    """Metadatos de un hallazgo (sin parámetros). Los textos se reaplican en el idioma pedido."""
    ws = _risk.retext(item.get('weaknesses', []), locale)
    return {
        'file': item.get('file'), 'line': item.get('line'), 'name': item.get('name'),
        'material_type': item.get('material_type'), 'algorithm': item.get('algorithm'),
        'key_size': item.get('key_size'), 'curve': item.get('curve'),
        'format': item.get('format'), 'encoding': item.get('encoding'),
        'protection': item.get('protection'), 'cipher': item.get('cipher'),
        'status': item.get('status'), 'detail_code': item.get('detail_code'),
        'context': item.get('context'), 'fingerprint_sha256_spki': item.get('fingerprint'),
        'certificate': item.get('cert'), 'tools': item.get('tools'),
        'weaknesses': [{k: w[k] for k in ('code', 'kind', 'severity', 'title', 'description', 'recommendation')} for w in ws],
        'risk': item.get('risk'),
        'risk_justification': [w['description'] for w in ws],
        'recommendations': sorted({w['recommendation'] for w in ws}),
        'assessment': {'confirmed_exposure': 'not_evaluated', 'active_use': 'not_evaluated'},
    }


def technical_report(scan: Dict[str, Any], locale: str = 'es') -> Dict[str, Any]:
    locale = _lang(locale)
    section = scan.get('crypto_keys') or {}
    return {
        'report': 'technical', 'includes_private_material': False,
        'generated_at': datetime.now(timezone.utc).isoformat(), 'scan_id': scan.get('id'),
        'source': scan.get('source'),
        'tools': section.get('tools', []),
        'items': [_item_view(i, locale) for i in section.get('items', [])],
        'limitations': _risk.LIMITATIONS[locale],
        'analysis_warning': section.get('warning'),
    }


def full_export(scan: Dict[str, Any], items_params: Dict[str, Dict[str, Any]], locale: str = 'es') -> Dict[str, Any]:
    """
    `items_params`: {item_id: {'status':..., 'public_params': [...], 'private_params': [...]}} ya
    recuperados (solo lo obtenido de forma fiable). Se une a la vista técnica de cada hallazgo.
    """
    rep = technical_report(scan, locale)
    rep['report'] = 'full'
    rep['includes_private_material'] = True
    rep['warning'] = ('Este archivo CONTIENE secretos criptográficos. Guárdalo cifrado, no lo compartas ni lo '
                      'subas a un repositorio.' if locale == 'es' else
                      'This file CONTAINS cryptographic secrets. Store it encrypted and do not share or commit it.')
    items = (scan.get('crypto_keys') or {}).get('items', [])
    for view, item in zip(rep['items'], items):
        got = items_params.get(item['id'])
        view['recovery'] = {'status': got['status'] if got else 'not_requested'}
        if got and got.get('status') in (_an.S_COMPLETED, _an.S_WEAK):
            view['public_parameters'] = got.get('public_params', [])
            if got.get('private_params'):  # una llave pública nunca se presenta como privada
                view['private_parameters'] = got['private_params']
    return rep


def render_txt(report: Dict[str, Any]) -> str:
    lines: List[str] = []
    add = lines.append
    add('PentaWark — Code Scan — Material criptográfico / Cryptographic material')
    add(f"Informe / Report: {report['report']}  |  Scan: {report.get('scan_id')}  |  {report.get('generated_at')}")
    if report.get('warning'):
        add('')
        add('!!! ' + report['warning'])
    add('')
    for it in report.get('items', []):
        add('=' * 78)
        add(f"{it['file']}:{it.get('line')}")
        add(f"  tipo/type: {it.get('material_type')}  algoritmo/algorithm: {it.get('algorithm')}  "
            f"tamaño/size: {it.get('key_size')}  formato/format: {it.get('format')} ({it.get('encoding')})")
        add(f"  protección/protection: {it.get('protection')}  estado/status: {it.get('status')}  riesgo/risk: {it.get('risk')}")
        for t in it.get('tools') or []:
            add(f"  herramienta/tool: {t.get('tool')} {t.get('version') or ''} · {t.get('operation')} -> {t.get('result')}"
                + (f" ({t['error']})" if t.get('error') else ''))
        for w in it.get('weaknesses', []):
            add(f"  [{w['severity']}] ({w['kind']}) {w['title']}: {w['description']}")
            add(f"      -> {w['recommendation']}")
        for key, title in (('public_parameters', 'PÚBLICOS / PUBLIC'), ('private_parameters', 'PRIVADOS / PRIVATE')):
            for p in it.get(key) or []:
                add(f"  {title} {p['name']} ({p.get('bits')} bits): {p['hex']}")
    add('')
    add('Limitaciones / Limitations:')
    for l in report.get('limitations', []):
        add(f'  - {l}')
    return '\n'.join(lines) + '\n'


def render(report: Dict[str, Any], fmt: str) -> str:
    return render_txt(report) if fmt == 'txt' else json.dumps(report, ensure_ascii=False, indent=2)
