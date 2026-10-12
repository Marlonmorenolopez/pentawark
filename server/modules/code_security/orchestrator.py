"""
Code Scan Orchestrator
Junta los scanners del motor de análisis de código ("Análisis de
Código", Grupo 3) y corre contra un directorio local ya preparado
(clonado desde GitHub, o extraído de un archivo subido).

Corre 7 scanners: Gitleaks + TruffleHog (secretos), BackdoorScanner
(heurística propia de webshells), Semgrep (SAST real), y Trivy +
Dependency-Check (dependencias vulnerables) y CryptoKeyScanner (material criptográfico). Todos operan sobre el mismo
árbol de archivos en disco.

CAMBIOS (diagnóstico del reporte real de DVWA):
  - Antes corrían en secuencia (el reporte tardó ~41 min) y el estado de
    TODAS las herramientas se marcaba "completed" al final, aunque alguna
    hubiera fallado. Ahora corren en paralelo (acotado) y cada una
    reporta su PROPIO estado real, duración y error, vía callbacks
    `on_start` / `on_done` que usa app.py para actualizar los pasos.
  - Una excepción en una herramienta ya no tumba el resto: queda como
    status='error' en esa herramienta y las demás siguen.
  - El resumen deduplica hallazgos repetidos y excluye lo que no es un
    hallazgo (los pasos con error/skipped se informan aparte).
"""

import logging
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Callable, Dict, List, Optional

from modules.code_security.backdoor_scanner import BackdoorScanner
from modules.code_security.gitleaks_scanner import GitleaksScanner
from modules.code_security.trufflehog_scanner import TruffleHogScanner
from modules.code_security.trivy_scanner import TrivyScanner
from modules.code_security.dependency_check import DependencyCheckScanner, ensure_database
from modules.code_security.semgrep_scanner import SemgrepScanner
from modules.code_security.crypto_inspector import CryptoKeyScanner

logger = logging.getLogger(__name__)

# Orden estable: (clave en el resultado, nombre del paso en la UI)
TOOLS = (
    ('gitleaks',         'Gitleaks'),
    ('trufflehog',       'TruffleHog'),
    ('backdoors',        'Backdoors'),
    ('semgrep',          'Semgrep'),
    ('trivy',            'Trivy'),
    ('dependency_check', 'Dependency-Check'),
    ('crypto_keys',      'Material criptográfico'),
)
TOOL_STEP_NAMES = {key: step for key, step in TOOLS}

# Estados válidos de cada herramienta
STATUS_COMPLETED = 'completed'   # corrió y devolvió resultado fiable (con o sin hallazgos)
STATUS_ERROR     = 'error'       # falló: NO se pudo verificar nada
STATUS_SKIPPED   = 'skipped'     # no se ejecutó (no instalada, base de datos sin lista...)
STATUS_TIMEOUT   = 'timeout'     # superó su límite de tiempo

_MAX_PARALLEL = 3  # semgrep y la JVM de dependency-check son pesados: no más de 3 a la vez


def _finalize(result: Any, duration: float) -> Dict[str, Any]:
    """Normaliza el resultado de un scanner: garantiza findings/error/status/duration_s."""
    if not isinstance(result, dict):
        result = {'findings': [], 'error': 'El scanner devolvió un resultado inválido'}
    result.setdefault('findings', [])
    result.setdefault('error', None)
    if not result.get('status'):
        result['status'] = STATUS_ERROR if result['error'] and not result['findings'] else STATUS_COMPLETED
    result['duration_s'] = round(duration, 1)
    return result


class CodeScanOrchestrator:
    """Corre los scanners reales de análisis de código contra un directorio local."""

    TOOL_STEP_NAMES = TOOL_STEP_NAMES  # clave interna -> nombre del paso en la UI

    def __init__(
        self,
        gitleaks_timeout: int = 120,
        trufflehog_timeout: int = 120,
        trufflehog_verify: bool = True,
        semgrep_timeout: int = 600,
        trivy_timeout: int = 120,
        trivy_image_timeout: int = 300,
        dependency_check_timeout: int = 600,
        nvd_api_key: str = None,
    ):
        self.gitleaks         = GitleaksScanner(timeout=gitleaks_timeout)
        self.trufflehog       = TruffleHogScanner(timeout=trufflehog_timeout, verify=trufflehog_verify)
        self.backdoors        = BackdoorScanner()
        self.semgrep          = SemgrepScanner(timeout=semgrep_timeout)
        self.trivy            = TrivyScanner(timeout=trivy_timeout, image_timeout=trivy_image_timeout)
        self.dependency_check = DependencyCheckScanner(timeout=dependency_check_timeout, nvd_api_key=nvd_api_key)
        self.crypto_keys      = CryptoKeyScanner()

        # La base NVD de Dependency-Check se sincroniza APARTE (en segundo plano),
        # nunca durante un scan. Si ya está lista y fresca esto no hace nada.
        try:
            if self.dependency_check.available:
                ensure_database(nvd_api_key)
        except Exception as e:  # noqa: BLE001 -- nunca debe impedir arrancar la app
            logger.warning("No se pudo iniciar la sincronización de la base de Dependency-Check: %s", e)

    def _run_tool(self, key: str, path: str,
                  on_start: Optional[Callable[[str], None]],
                  on_done: Optional[Callable[[str, Dict[str, Any]], None]]) -> Dict[str, Any]:
        scanner = getattr(self, key)
        started = time.monotonic()
        if on_start:
            try:
                on_start(key)
            except Exception:  # noqa: BLE001 -- un fallo de UI no debe abortar el scan
                logger.exception("on_start(%s) falló", key)
        try:
            result = _finalize(scanner.scan(path), time.monotonic() - started)
        except Exception as e:  # noqa: BLE001 -- aislar: una herramienta rota no tumba las demás
            logger.exception("Scanner %s lanzó una excepción", key)
            result = _finalize({'findings': [], 'status': STATUS_ERROR,
                                'error': f'Error interno ejecutando {TOOL_STEP_NAMES[key]}: {e}'},
                               time.monotonic() - started)
        if on_done:
            try:
                on_done(key, result)
            except Exception:  # noqa: BLE001
                logger.exception("on_done(%s) falló", key)
        logger.info("CodeScan %s: status=%s hallazgos=%d en %.1fs%s", key, result['status'],
                    len(result['findings']), result['duration_s'],
                    f" error={result['error']}" if result.get('error') else '')
        return result

    def scan_directory(
        self,
        path: str,
        on_start: Optional[Callable[[str], None]] = None,
        on_done: Optional[Callable[[str, Dict[str, Any]], None]] = None,
    ) -> Dict[str, Any]:
        """
        Corre los 7 scanners contra `path` (en paralelo acotado) y arma un resumen.

        Args:
            on_start(key): se llama cuando una herramienta EMPIEZA a correr.
            on_done(key, result): se llama cuando una herramienta TERMINA (con su
                resultado y estado reales).

        Returns:
            Dict con: gitleaks, trufflehog, backdoors, semgrep, trivy,
            dependency_check (cada uno con status/error/duration_s), summary
            (conteos por severidad, deduplicados), y tools (resumen de estado
            por herramienta).
        """
        logger.info("CodeScanOrchestrator: iniciando análisis de %s", path)

        # Las más lentas primero para que el paralelismo acotado las solape con las rápidas.
        order = ['dependency_check', 'semgrep', 'trivy', 'gitleaks', 'trufflehog', 'backdoors', 'crypto_keys']
        results: Dict[str, Dict[str, Any]] = {}
        with ThreadPoolExecutor(max_workers=_MAX_PARALLEL, thread_name_prefix='codescan') as pool:
            futures = {pool.submit(self._run_tool, key, path, on_start, on_done): key for key in order}
            for fut in as_completed(futures):
                results[futures[fut]] = fut.result()

        # Defensa en profundidad: el material crudo de llaves (`_blobs`) es transitorio; app.py lo
        # mueve a la custodia en on_done. Si por cualquier razón sigue aquí, se elimina ya.
        for r in results.values():
            r.pop('_blobs', None)

        summary = self._build_summary(results)
        tools = {
            key: {
                'status':     results[key]['status'],
                'findings':   len(results[key]['findings']),
                'duration_s': results[key]['duration_s'],
                'error':      results[key].get('error'),
                'warning':    results[key].get('warning'),
            }
            for key, _ in TOOLS
        }
        failed = [TOOL_STEP_NAMES[k] for k, t in tools.items() if t['status'] != STATUS_COMPLETED]
        summary['tools_completed'] = len(TOOLS) - len(failed)
        summary['tools_total']     = len(TOOLS)
        summary['tools_failed']    = failed

        logger.info("CodeScanOrchestrator: análisis completo — %s", summary)

        out: Dict[str, Any] = {key: results[key] for key, _ in TOOLS}
        out['summary'] = summary
        out['tools']   = tools
        return out

    @staticmethod
    def _dedupe(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        seen, unique = set(), []
        for f in findings:
            # package + installed_version van en la clave: el MISMO CVE en versiones distintas de un
            # paquete (ej. minimist 0.0.8 / 1.2.0 / 1.2.5) son instancias distintas a corregir, no
            # duplicados. Antes se fundían y el resumen contaba 8 críticos en vez de 12.
            key = (f.get('file') or f.get('target'), f.get('line'),
                   f.get('rule_id') or f.get('type') or f.get('detector') or f.get('vuln_id'),
                   f.get('package'), f.get('installed_version'), f.get('severity'))
            if key in seen:
                continue
            seen.add(key)
            unique.append(f)
        return unique

    def _build_summary(self, results: Dict[str, Dict[str, Any]]) -> Dict[str, int]:
        counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'unknown': 0}
        for result in results.values():
            for finding in self._dedupe(result.get('findings', [])):
                sev = (finding.get('severity') or 'unknown').lower()
                counts[sev] = counts.get(sev, 0) + 1
        counts['total'] = sum(counts.values())
        return counts
