"""
Semgrep Scanner (real)
Corre el binario real de Semgrep vía subprocess — SAST (Static
Application Security Testing) real, cuarta pieza de detección del Grupo
3 junto a Gitleaks/TruffleHog (secretos) y Trivy/Dependency-Check
(dependencias).

Diferencia real con BackdoorScanner (mi heurística propia): Semgrep usa
~280 reglas reales mantenidas por la comunidad (semgrep-rules en GitHub)
que entienden la SINTAXIS del lenguaje, no solo texto -- detecta SQLi,
XSS, path traversal, SSRF, deserialización insegura, y mucho más que los
pocos patrones de webshell que cubre mi heurística. BackdoorScanner
sigue teniendo su lugar: es más rápido y apunta específicamente a
webshells/backdoors ya insertados, mientras que Semgrep apunta a
vulnerabilidades en código legítimo que un atacante podría explotar.

Nota de instalación: el registro de reglas de semgrep.dev puede estar
bloqueado en redes con egress restringido -- por eso este proyecto NO
usa `--config auto` ni `--config p/...` (ambos requieren red en el
momento del escaneo). En su lugar, el Dockerfile clona el repo público
de reglas y las consolida en /opt/semgrep-rules en el build, así que
esto corre 100% offline en runtime.

Costo de arranque real (confirmado en pruebas): cargar ~280 reglas
toma un tiempo fijo notable (decenas de segundos) independiente del
tamaño del código escaneado -- por diseño, el timeout por defecto de
este módulo es generoso.
"""

import json
import logging
import shutil
import subprocess
from pathlib import Path
from typing import Any, Dict, List

logger = logging.getLogger(__name__)

_BIN = 'semgrep'
_RULES_DIR = '/opt/semgrep-rules'

_SEMGREP_SEVERITY = {'ERROR': 'high', 'WARNING': 'medium', 'INFO': 'low'}


def _as_list(value: Any) -> List[str]:
    """
    Las reglas de Semgrep declaran `cwe`/`owasp` a veces como lista y a veces como un
    solo string (varía por regla/lenguaje). Se normaliza SIEMPRE a lista de strings:
    el frontend hacía `.map()` directo y un string suelto rompía toda la página.
    """
    if value is None or value == '':
        return []
    if isinstance(value, (list, tuple, set)):
        return [str(v) for v in value if v not in (None, '')]
    return [str(value)]


class SemgrepScanner:
    """Wrapper del binario real de Semgrep — SAST con reglas reales de la comunidad."""

    def __init__(self, timeout: int = 600):
        self.timeout       = timeout
        self.rules_present = Path(_RULES_DIR).is_dir() and any(Path(_RULES_DIR).iterdir())
        self.available      = shutil.which(_BIN) is not None and self.rules_present
        if not shutil.which(_BIN):
            logger.warning("Semgrep: el binario '%s' no está instalado en el servidor.", _BIN)
        elif not self.rules_present:
            logger.warning("Semgrep: no hay reglas consolidadas en %s -- revisar el build del Dockerfile.", _RULES_DIR)

    def scan(self, root_path: str) -> Dict[str, Any]:
        """
        Corre Semgrep contra `root_path` con las reglas consolidadas.

        Returns:
            Dict con: findings (file RELATIVO al repo, line, rule_id, rule,
            message, severity, cwe, owasp), error, warning, status
            ('completed'|'error'|'skipped'|'timeout'), files_scanned,
            rules_loaded.
        """
        root = Path(root_path)
        if not root.exists() or not root.is_dir():
            return {'findings': [], 'error': f'Directorio no encontrado: {root_path}', 'status': 'error'}

        if not self.available:
            reason = 'Semgrep no está instalado en el servidor' if not shutil.which(_BIN) \
                else f'Sin reglas consolidadas en {_RULES_DIR} (revisar build)'
            return {'findings': [], 'error': reason, 'status': 'skipped'}

        report_path = f'{root}.semgrep-report.json'
        rules_loaded = len(list(Path(_RULES_DIR).glob('*.y*ml')))

        try:
            try:
                proc = subprocess.run(
                    [
                        _BIN, 'scan',
                        '--config', _RULES_DIR,
                        '--json',
                        '--output', report_path,
                        '--quiet',
                        '--disable-version-check',
                        '--metrics', 'off',  # no mandar telemetría a semgrep.dev
                        '--no-git-ignore',   # el repo clonado trae .gitignore: igual se analiza todo
                        '--exclude', 'node_modules', '--exclude', '.git',
                        str(root),
                    ],
                    stdin=subprocess.DEVNULL,
                    capture_output=True, text=True, timeout=self.timeout,
                )
            except subprocess.TimeoutExpired:
                return {'findings': [], 'error': f'Semgrep no terminó en {self.timeout}s', 'status': 'timeout',
                        'rules_loaded': rules_loaded}
            except FileNotFoundError:
                return {'findings': [], 'error': 'Semgrep no está instalado en el servidor', 'status': 'skipped'}

            report_file = Path(report_path)
            if not report_file.exists():
                detail = (proc.stderr or proc.stdout or '').strip()[-400:]
                return {'findings': [], 'status': 'error', 'rules_loaded': rules_loaded,
                        'error': f'Semgrep no generó reporte (código {proc.returncode}). {detail}'.strip()}

            try:
                data = json.loads(report_file.read_text(encoding='utf-8') or '{}')
            except ValueError as e:
                return {'findings': [], 'error': f'Error parseando reporte de Semgrep: {e}', 'status': 'error'}

            root_str = str(root).rstrip('/') + '/'
            findings: List[Dict[str, Any]] = []
            seen = set()
            for item in data.get('results', []):
                extra    = item.get('extra', {})
                metadata = extra.get('metadata', {})
                start    = item.get('start') or {}
                path     = item.get('path') or ''
                if path.startswith(root_str):  # no exponer la ruta temporal interna del servidor
                    path = path[len(root_str):]
                rule_id = item.get('check_id') or ''
                key = (path, start.get('line'), start.get('col'), rule_id)
                if key in seen:  # Semgrep puede repetir el mismo match (ej. regla con varios patrones)
                    continue
                seen.add(key)
                findings.append({
                    'file':     path,
                    'line':     start.get('line'),
                    'rule_id':  rule_id,
                    'rule':     rule_id.rsplit('.', 1)[-1],
                    'message':  extra.get('message'),
                    'severity': _SEMGREP_SEVERITY.get(extra.get('severity'), 'medium'),
                    'cwe':      _as_list(metadata.get('cwe')),
                    'owasp':    _as_list(metadata.get('owasp')),
                })

            # Errores reportados por Semgrep: los PartialParsing/warn son ruido normal
            # (archivo con sintaxis rara); los demás (regla inválida, timeout de regla)
            # sí significan cobertura incompleta, y se dicen con nombre y apellido.
            real_errors = [e for e in data.get('errors', []) or []
                           if e.get('level') != 'warn' and e.get('type') not in ('PartialParsing', 'Syntax error')]
            warning = None
            if real_errors:
                samples = '; '.join(
                    (e.get('message') or e.get('type') or 'error')[:120].replace('\n', ' ')
                    for e in real_errors[:3])
                warning = f'{len(real_errors)} error(es) durante el análisis, cobertura posiblemente incompleta: {samples}'
                logger.warning("Semgrep: %s", warning)

            scanned = (data.get('paths') or {}).get('scanned') or []
            return {
                'findings':      findings,
                'error':         None,
                'warning':       warning,
                'status':        'completed',
                'files_scanned': len(scanned),
                'rules_loaded':  rules_loaded,
            }

        finally:
            Path(report_path).unlink(missing_ok=True)
