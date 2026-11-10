"""
Modelo unificado de Findings (SecureScan Pro).

Problema que resuelve: cada familia de scan (web/code/osint) guarda sus
resultados en una forma distinta (vulnerabilities[] vs gitleaks.findings[]
vs breaches[]). Antes de este módulo, comparison.py tenía 3 extractores
separados con lógica de fingerprint duplicada, y ni scoring.py ni
reporter.py podían recorrer "todos los hallazgos de un scan" de forma
genérica.

Este módulo NO reemplaza los campos existentes en el dict de scan (no
rompe nada que ya lea directamente 'vulnerabilities', 'gitleaks', etc.)
-- es una capa de traducción adicional: normalize_findings(scan) produce
una lista de Finding con un schema común, que comparison.py, scoring.py
y reporter.py pueden consumir sin conocer los detalles de cada scanner.

Schema de un Finding (dict, no dataclass a propósito -- json-serializable
directo, igual convención que el resto del proyecto):
    {
        'id':        str,   # fingerprint estable (16 hex, mismo algoritmo que ya usaba comparison.py)
        'tool':      str,   # 'zap' | 'nuclei' | 'gitleaks' | 'semgrep' | 'xposedornot' | ...
        'family':    str,   # 'web' | 'code' | 'osint'
        'title':     str,
        'severity':  str,   # 'critical'|'high'|'medium'|'low'|'info'|'' (vacío si la herramienta no la reporta)
        'target':    str,   # host/URL/archivo/email según corresponda
        'evidence':  str,   # descripción corta o snippet, lo que haya
        'cve':       str,   # '' si no aplica
        'category':  str,   # Fase 4 (2026-11): categoría canónica de vulnerabilidad
                             # (ver _categorize() abajo) -- '' si no se pudo inferir.
        'parameter': str,   # Fase 4: parámetro/endpoint específico cuando la
                             # herramienta lo reporta (SQLMap/InjectionScanner/
                             # Interactsh) -- '' si no aplica.
        'raw':       Any,   # objeto original completo, por si el consumidor necesita más detalle
    }

FASE 4 DEL PLAN DE LA "Auditoría de cobertura de vulnerabilidades —
PentaWark" (2026-11, autorizada explícitamente por el usuario):
"Unificar dedup entre findings.py y scoring.py bajo un criterio común" --
antes de esta fase, `dedupe_findings()` (usado por Code Scan/OSINT, y
ahora también por el Web Scan -- ver más abajo) solo fusionaba por
(cve, target), mientras que `utils/scoring.py::calculate_security_score()`
(usado solo por el Web Scan) tenía su PROPIO dedup desconectado por
(nombre, severidad, tool) -- dos sistemas distintos, criterios distintos,
sin relación entre sí.

Se agregó `category` (ver `_categorize()`) y `parameter` al schema de
Finding, y `dedupe_findings()` ahora también fusiona por
`(category, target, parameter)` cuando no hay cve+target disponibles --
esto cubre vulnerabilidades web (SQLi/XSS/XXE/SSRF/...) que normalmente
no tienen CVE pero sí categoría+endpoint, el caso que el dedup anterior
simplemente no cubría. `calculate_security_score()` en sí NO se tocó
(sigue teniendo sus propios ~17 tests unitarios atados a su dedup por
nombre/severidad/tool, que ya tenía su propio fix documentado y
confirmado contra un reporte real) -- en vez de reemplazarlo, el Web Scan
(server/app.py, paso Scoring) ahora pasa primero por
`dedupe_findings(normalize_findings(...))` ANTES de llamar a
`calculate_security_score()`, igual que ya hacían Code Scan y OSINT. El
dedup de `calculate_security_score()` sigue corriendo después, sobre una
lista ya depurada -- es idempotente (no vuelve a fusionar nada que ya no
lo estuviera), así que esto es puramente aditivo y no cambia ningún
resultado de esos tests existentes.
"""

import hashlib
from typing import Any, Dict, List


def _fp(*parts: str) -> str:
    normalized = '|'.join((p or '').strip().lower() for p in parts)
    return hashlib.sha256(normalized.encode('utf-8')).hexdigest()[:16]


def _norm_severity(sev: str) -> str:
    sev = (sev or '').strip().lower()
    return sev if sev in ('critical', 'high', 'medium', 'low', 'info') else (sev or '')


# Fase 4 (2026-11): mapa de InjectionType (modules/pentesting/
# injection_scanner.py) -- la señal MÁS confiable de categoría porque
# viene de un enum cerrado, no de parsear texto libre. Cubre tanto
# InjectionScanner como SQLMapFinding cuando usan el mismo campo
# 'injection_type'.
_INJECTION_TYPE_CATEGORY = {
    'sql_error_based': 'sqli', 'sql_union_based': 'sqli', 'sql_boolean_blind': 'sqli',
    'sql_time_based': 'sqli', 'sql_auth_bypass': 'sqli', 'sql_stacked_queries': 'sqli',
    'sql_second_order': 'sqli',
    'nosql_injection': 'nosqli', 'xpath_injection': 'xpath', 'xxe': 'xxe',
    'xss_reflected': 'xss', 'xss_stored': 'xss', 'xss_dom': 'xss',
    'command_injection': 'cmdi', 'path_traversal': 'path_traversal',
    'ssrf': 'ssrf', 'ssti': 'ssti', 'ldap_injection': 'ldap',
}

# Fase 4: mapa directo por tool para fuentes de un solo propósito, donde
# la herramienta YA ES la categoría (más confiable que adivinar por texto).
_TOOL_CATEGORY = {
    'gitleaks': 'secrets', 'trufflehog': 'secrets',
    'backdoors': 'backdoor',
    'xposedornot': 'breach', 'username_search': 'osint_identity', 'theharvester': 'osint_recon',
}

# Fase 4: heurística de respaldo por palabras clave en el título --
# MEJOR ESFUERZO, documentado como tal. Solo se usa cuando lo anterior no
# resolvió nada. Es deliberadamente de bajo riesgo: una categoría mal
# inferida (o '' si nada coincide) solo puede hacer que dedupe_findings()
# DEJE de fusionar dos hallazgos que en realidad eran el mismo (falso
# negativo, inofensivo -- simplemente no se fusionan, igual que antes de
# esta Fase) -- nunca fusiona dos hallazgos genuinamente distintos, porque
# el criterio de fusión (ver dedupe_findings) exige TAMBIÉN que coincidan
# target+parameter, no solo la categoría.
_KEYWORD_CATEGORY = [
    ('sql injection', 'sqli'), ('sqli', 'sqli'),
    ('cross-site scripting', 'xss'), ('xss', 'xss'),
    ('xxe', 'xxe'), ('xml external entity', 'xxe'),
    ('ssrf', 'ssrf'), ('server-side request forgery', 'ssrf'),
    ('command injection', 'cmdi'), ('os command', 'cmdi'),
    ('path traversal', 'path_traversal'), ('directory traversal', 'path_traversal'),
    ('template injection', 'ssti'), ('ssti', 'ssti'),
    ('ldap injection', 'ldap'),
    ('nosql', 'nosqli'),
    ('xpath', 'xpath'),
    ('csrf', 'csrf'), ('cross-site request forgery', 'csrf'),
    ('jwt', 'jwt'),
    ('graphql', 'graphql'),
    ('certificate', 'tls'), ('tls', 'tls'), (' ssl', 'tls'),
    ('hardcoded secret', 'secrets'), ('credential', 'secrets'), ('api key', 'secrets'),
    ('backdoor', 'backdoor'),
]


def _categorize(tool: str, title: str, injection_type: str = '') -> str:
    """
    Devuelve una categoría canónica de vulnerabilidad para usar como
    parte de la clave de fusión de `dedupe_findings()`. MEJOR ESFUERZO --
    ver nota de riesgo en `_KEYWORD_CATEGORY` arriba. Nunca lanza.
    """
    if injection_type:
        cat = _INJECTION_TYPE_CATEGORY.get(injection_type)
        if cat:
            return cat
    cat = _TOOL_CATEGORY.get((tool or '').strip().lower())
    if cat:
        return cat
    title_lower = (title or '').strip().lower()
    for keyword, cat in _KEYWORD_CATEGORY:
        if keyword in title_lower:
            return cat
    return ''


def _finding(fid: str, tool: str, family: str, title: str, severity: str = '',
             target: str = '', evidence: str = '', cve: str = '', raw: Any = None,
             parameter: str = '', injection_type: str = '') -> Dict[str, Any]:
    return {
        'id': fid, 'tool': tool, 'family': family, 'title': title or 'Finding',
        'severity': _norm_severity(severity), 'target': target,
        'evidence': evidence, 'cve': cve or '',
        'category': _categorize(tool, title, injection_type),
        'parameter': parameter or '',
        'raw': raw,
    }


# ── Web Scan ─────────────────────────────────────────────────────────────────

def _from_web(scan: Dict[str, Any]) -> List[Dict[str, Any]]:
    out = []
    for v in scan.get('vulnerabilities', []) or []:
        out.append(_finding(
            _fp(v.get('tool', 'zap'), v.get('name', ''), v.get('url', '')),
            v.get('tool', 'zap'), 'web', v.get('name', 'Finding'), v.get('severity', ''),
            target=v.get('url', ''), evidence=v.get('description', ''), raw=v,
            parameter=v.get('parameter', ''),
        ))
    for n in scan.get('nuclei_findings', []) or []:
        out.append(_finding(
            _fp('nuclei', n.get('template', n.get('name', '')), n.get('url', n.get('host', ''))),
            'nuclei', 'web', n.get('name') or n.get('template', 'Finding'), n.get('severity', ''),
            target=n.get('url', n.get('host', '')), raw=n,
        ))
    for e in scan.get('exploits', []) or []:
        out.append(_finding(
            _fp('searchsploit', e.get('title', '')),
            'searchsploit', 'web', e.get('title', 'Exploit'), evidence=e.get('type', ''), raw=e,
        ))
    for m in scan.get('metasploit', []) or []:
        out.append(_finding(
            _fp('metasploit', m.get('module', ''), m.get('host', '')),
            'metasploit', 'web', m.get('title') or m.get('module', 'Finding'), m.get('severity', ''),
            target=m.get('host', ''), raw=m,
        ))
    # Fase 4 (2026-11): hallazgos confirmados por Interactsh (ver Fase 3,
    # orchestrator.py::collect_oast_findings()) -- antes de esta Fase no
    # entraban al modelo unificado de findings.py en absoluto (solo se
    # sumaban directamente en server/app.py). 'severity' y 'parameter' ya
    # vienen listos en el dict que produce collect_oast_findings().
    for o in scan.get('oast_findings', []) or []:
        out.append(_finding(
            _fp('interactsh', o.get('name', ''), o.get('url', ''), o.get('parameter', '')),
            'interactsh', 'web', o.get('name', 'Finding'), o.get('severity', ''),
            target=o.get('url', ''), evidence=o.get('description', ''), raw=o,
            parameter=o.get('parameter', ''),
        ))
    for s in scan.get('sqli_results', []) or []:
        # FIX (auditoría pentesting): 'sqli_results' no contiene SOLO hallazgos de
        # SQLMap -- orchestrator.run_injection_scan() (InjectionScanner, 10
        # técnicas: XSS, SSRF, XXE, command injection, LDAP, etc., ver
        # modules/pentesting/injection_scanner.py) guarda ahí sus resultados
        # también, como fallback/complemento de SQLMap. Antes, esta función
        # etiquetaba TODO lo que había en 'sqli_results' como
        # tool='sqlmap' y title=f"SQL Injection: {parametro}" sin mirar el
        # tipo real -- un XSS o un SSRF detectado por InjectionScanner
        # aparecía en el modelo unificado de hallazgos (y por lo tanto en
        # scoring/reportes/dedupe) como si fuera una inyección SQL. Además,
        # como el fingerprint se calculaba con tool fijo 'sqlmap', dos
        # hallazgos de tipos distintos sobre el mismo parámetro/URL podían
        # fusionarse incorrectamente en dedupe_findings(). Ahora se respeta
        # el 'tool' y 'name' reales que cada scanner ya reporta
        # (SQLMapFinding.to_dict() e InjectionFinding.to_dict() ambos traen
        # 'tool' y 'name' propios).
        tool  = s.get('tool') or 'sqlmap'
        title = s.get('name') or (f"SQL Injection: {s.get('parameter', '')}" if tool == 'sqlmap' else 'Finding')
        out.append(_finding(
            _fp(tool, title, s.get('url', ''), s.get('parameter', '')),
            tool, 'web', title, s.get('severity', 'high'),
            target=s.get('url', ''), evidence=s.get('evidence', '') or s.get('description', ''), raw=s,
            # Fase 4 (2026-11): 'parameter' para la clave de fusión extendida
            # de dedupe_findings(); 'injection_type' (InjectionFinding.to_dict())
            # es la señal MÁS confiable de categoría para estos hallazgos --
            # SQLMapFinding no trae injection_type, por eso tool=='sqlmap'
            # sigue cayendo en la heurística por palabras clave de _categorize().
            parameter=s.get('parameter', ''), injection_type=s.get('injection_type', ''),
        ))
    return out


# ── Code Scan ────────────────────────────────────────────────────────────────

_CODE_TOOLS = ('gitleaks', 'trufflehog', 'backdoors', 'semgrep', 'trivy', 'dependency_check', 'crypto_keys')


def _code_title(f: Dict[str, Any]) -> str:
    """
    Título legible y ESTABLE de un hallazgo de código. Antes solo se leía 'rule'/'title',
    que ningún scanner de código devuelve (usan rule_id / type / detector / vuln_id) --
    todos caían en 'Finding' y, como el fingerprint usaba ese título, los hallazgos de
    dependencias (sin línea) del mismo archivo se fundían en UNO SOLO.
    """
    base = (f.get('rule') or f.get('rule_id') or f.get('type') or f.get('detector')
            or f.get('vuln_id') or f.get('title') or 'Finding')
    if f.get('package') and f.get('vuln_id'):
        return f"{f['vuln_id']} ({f['package']})"
    return str(base)


def _from_code(scan: Dict[str, Any]) -> List[Dict[str, Any]]:
    out = []
    for tool in _CODE_TOOLS:
        section = scan.get(tool) or {}
        for f in section.get('findings', []) or []:
            title  = _code_title(f)
            target = f.get('file') or f.get('target') or ''
            if f.get('package'):
                # (cve, target) es la clave de fusión de dedupe_findings: sin la instancia del paquete,
                # el mismo CVE en 4 versiones de `minimist` se contaba como UN solo hallazgo.
                ver = f.get('installed_version')
                target = f"{target} ({f['package']}{'@' + ver if ver else ''})"
            vuln   = f.get('vuln_id') or ''
            out.append(_finding(
                _fp(tool, title, target, str(f.get('line', '')), f.get('package', '') or '', f.get('installed_version', '') or ''),
                tool, 'code', title, f.get('severity', ''),
                target=target,
                evidence=f.get('description') or f.get('message') or f.get('title') or '',
                cve=f.get('cve') or (vuln if vuln.upper().startswith('CVE-') else ''),
                raw=f,
            ))
    return out


# ── OSINT ────────────────────────────────────────────────────────────────────

def _from_osint(scan: Dict[str, Any]) -> List[Dict[str, Any]]:
    out = []
    for b in scan.get('breaches', []) or []:
        out.append(_finding(
            _fp('breach', b.get('name', b.get('source', ''))),
            'xposedornot', 'osint', b.get('name') or b.get('source', 'Breach'),
            'medium', target=scan.get('email', ''), evidence=b.get('date', ''), raw=b,
        ))
    for r in scan.get('found', []) or []:
        out.append(_finding(
            _fp('username_match', r.get('site', ''), r.get('url', '')),
            'username_search', 'osint', r.get('site', 'Match'),
            target=scan.get('username', ''), evidence=r.get('url', ''), raw=r,
        ))
    for e in scan.get('emails', []) or []:
        out.append(_finding(_fp('harvester_email', e), 'theharvester', 'osint', e, target=scan.get('domain', ''), raw=e))
    for h in scan.get('hosts', []) or []:
        out.append(_finding(_fp('harvester_host', h), 'theharvester', 'osint', h, target=scan.get('domain', ''), raw=h))
    return out


def detect_family(scan: Dict[str, Any]) -> str:
    scan_type = (scan.get('scan_type') or '').strip()
    if scan_type == 'code':
        return 'code'
    if scan_type.startswith('osint'):
        return 'osint'
    return 'web'


def normalize_findings(scan: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Punto de entrada único: detecta la familia y devuelve Findings normalizados."""
    family = detect_family(scan)
    if family == 'code':
        return _from_code(scan)
    if family == 'osint':
        return _from_osint(scan)
    return _from_web(scan)


def _merge_into(existing: Dict[str, Any], f: Dict[str, Any]) -> None:
    """Fusiona `f` dentro de `existing` in-place: acumula herramientas y
    conserva la severidad más alta. Compartido por las dos claves de
    fusión de abajo."""
    tools = set(existing.get('_merged_tools', [existing['tool']]))
    tools.add(f['tool'])
    existing['_merged_tools'] = sorted(tools)
    existing['tool'] = ' + '.join(sorted(tools))
    sev_order = {'critical': 5, 'high': 4, 'medium': 3, 'low': 2, 'info': 1, '': 0}
    if sev_order.get(f['severity'], 0) > sev_order.get(existing['severity'], 0):
        existing['severity'] = f['severity']


def dedupe_findings(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Deduplicación dentro de un mismo scan: si dos herramientas distintas
    reportan el MISMO problema real, se fusiona en un solo Finding con
    ambas herramientas listadas -- en vez de contarlo dos veces en el
    score o mostrarlo duplicado en el reporte. Dos criterios de fusión,
    en orden de prioridad:

    1. (cve, target) cuando AMBOS están presentes -- el criterio
       original, sin cambios (ej. Nuclei Y ZAP encuentran el mismo CVE en
       la misma URL; Trivy Y dependency-check reportan el mismo CVE sobre
       el mismo paquete).
    2. Fase 4 (2026-11, autorizada por el usuario) -- (category, target,
       parameter) cuando `category` fue inferida (ver `_categorize()`) y
       `target` está presente. Cubre el caso que (1) no cubre: vulnerabi-
       lidades web sin CVE (SQLi/XSS/XXE/SSRF/...) que dos motores
       distintos (ej. ZAP e InjectionScanner) detectan sobre el MISMO
       endpoint/parámetro con nombres de hallazgo distintos.

    Deliberadamente conservador en ambos casos: nunca fusiona por
    título/nombre solo. Un hallazgo que no cumple ninguno de los dos
    criterios pasa sin tocar (comportamiento sin cambios respecto a antes
    de la Fase 4 para todo lo que ya tenía cve+target).
    """
    merged_by_cve: Dict[str, Dict[str, Any]] = {}
    merged_by_category: Dict[str, Dict[str, Any]] = {}
    passthrough: List[Dict[str, Any]] = []

    for f in findings:
        if f['cve'] and f['target']:
            key = _fp(f['cve'], f['target'])
            if key in merged_by_cve:
                _merge_into(merged_by_cve[key], f)
            else:
                merged_by_cve[key] = dict(f)
        elif f.get('category') and f['target']:
            key = _fp(f['category'], f['target'], f.get('parameter', ''))
            if key in merged_by_category:
                _merge_into(merged_by_category[key], f)
            else:
                merged_by_category[key] = dict(f)
        else:
            passthrough.append(f)

    return list(merged_by_cve.values()) + list(merged_by_category.values()) + passthrough


def to_vulnerability_list(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Fase 4 (2026-11, autorizada por el usuario): convierte Findings
    normalizados/deduplicados de vuelta a la forma "vulnerabilidad cruda"
    que `utils/scoring.py::calculate_security_score()` espera (los mismos
    campos que ya traía cada vuln antes de pasar por este módulo --
    'name'/'title', 'tool' o 'source', 'severity', 'url', etc.), usando
    el dict original (`raw`) como base y aplicando encima SOLO la fusión
    de `tool`/`severity` que `dedupe_findings()` ya calculó (ej.
    tool pasa de 'zap' a 'zap + nuclei' si se fusionaron).

    Un Finding sin 'raw' (no debería pasar con los `_from_*` de este
    módulo, pero por si acaso) se omite en vez de inventar un dict vacío
    -- nunca se fabrica una vulnerabilidad sin datos reales detrás.
    """
    out = []
    for f in findings:
        if f.get('raw') is None:
            continue
        vuln = dict(f['raw'])
        vuln['tool'] = f['tool']
        vuln['severity'] = f['severity']
        out.append(vuln)
    return out
