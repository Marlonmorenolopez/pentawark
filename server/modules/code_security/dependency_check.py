"""
OWASP Dependency-Check Scanner (real)
Corre el binario real de OWASP Dependency-Check vía subprocess —
dependencias vulnerables, segunda fuente del Grupo 3 junto a Trivy.

DISEÑO (reescrito tras diagnosticar el reporte real de DVWA, donde este
paso terminó "completed" con 0 hallazgos y el error
"Unable to obtain an exclusive lock on the H2 database to perform
updates / No documents exist"):

Causas raíz encontradas:
  1. La base NVD estaba VACÍA ("No documents exist"): el pre-poblado del
     Dockerfile corre con `|| true` y, sin NVD_API_KEY, falla en silencio.
  2. La base vivía en /opt/dependency-check/data (propiedad de root),
     pero el contenedor corre como usuario `scanner`: no podía tomar el
     candado exclusivo de H2 para actualizar ("exclusive lock ...").
  3. Cada scan intentaba actualizar la base (--noupdate estaba comentado)
     -- con 2 workers de gunicorn + celery eso son varios procesos Java
     peleando por el mismo candado.
  4. `self.timeout = 10800` ignoraba el parámetro: un scan podía colgar
     horas esperando.
  5. El resultado vacío con error se mostraba como "completed".

Solución:
  - La base vive en un directorio ESCRIBLE por el usuario de la app
    (DEPENDENCY_CHECK_DATA, por defecto /opt/dependency-check-data),
    montado como volumen persistente y compartido (ver docker-compose).
  - La actualización de la base es una operación APARTE (hilo en segundo
    plano, `ensure_database()`), protegida por un candado de archivo
    (flock) que también toman los scans -- nunca corren a la vez.
  - Los scans corren SIEMPRE con --noupdate. Si la base no está lista
    devuelven status='skipped' con un mensaje claro (en vez de colgarse
    o fingir que no hay vulnerabilidades).
  - El timeout es el que se pasa por parámetro, y al vencer se mata el
    grupo de procesos completo (script de shell + JVM hija).
"""

import json
import logging
import os
import shutil
import signal
import subprocess
import tempfile
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

try:  # fcntl solo existe en Unix; el servidor corre en Linux
    import fcntl
except ImportError:  # pragma: no cover
    fcntl = None

logger = logging.getLogger(__name__)

_BIN = 'dependency-check.sh'
_DATA_DIR = os.getenv('DEPENDENCY_CHECK_DATA', '/opt/dependency-check-data')
_DB_FILE = 'odc.mv.db'
# Una base NVD real pesa cientos de MB; una recién creada/vacía pesa unos KB.
_MIN_DB_BYTES = 20 * 1024 * 1024
# NVD recomienda actualizar al menos cada 4 días; más allá de 7 se avisa.
_STALE_AFTER_DAYS = 7
_UPDATE_TIMEOUT = int(os.getenv('DEPENDENCY_CHECK_UPDATE_TIMEOUT', 10800))
_LOCK_WAIT = int(os.getenv('DEPENDENCY_CHECK_LOCK_WAIT', 120))

_SEVERITY_MAP = {
    'critical': 'critical', 'high': 'high', 'medium': 'medium',
    'moderate': 'medium', 'low': 'low', 'info': 'low', 'informational': 'low',
}

# Estado de la actualización en segundo plano (por proceso).
_update_lock  = threading.Lock()
_update_state: Dict[str, Any] = {'running': False, 'started': None, 'last_error': None, 'last_ok': None}


def _run_group(cmd: List[str], timeout: int) -> Tuple[int, str, str]:
    """
    Corre `cmd` en su propio grupo de procesos. Si vence `timeout` mata el
    grupo COMPLETO (script de shell + JVM hija) y relanza TimeoutExpired.
    Matar solo el script deja la JVM huérfana con el candado de H2 tomado.
    """
    proc = subprocess.Popen(
        cmd,
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True, start_new_session=True,
    )
    try:
        stdout, stderr = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        except ProcessLookupError:
            pass
        try:
            proc.communicate(timeout=10)
        except Exception:
            pass
        raise
    return proc.returncode, stdout or '', stderr or ''


class _FileLock:
    """Candado exclusivo entre PROCESOS (flock) sobre la base de datos."""

    def __init__(self, path: str):
        self.path = path
        self._fh = None

    def acquire(self, wait: float) -> bool:
        if fcntl is None:
            return True
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        self._fh = open(self.path, 'a+')
        deadline = time.monotonic() + max(wait, 0)
        while True:
            try:
                fcntl.flock(self._fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
                return True
            except OSError:
                if time.monotonic() >= deadline:
                    self._fh.close()
                    self._fh = None
                    return False
                time.sleep(1)

    def release(self) -> None:
        if self._fh is not None:
            try:
                if fcntl is not None:
                    fcntl.flock(self._fh, fcntl.LOCK_UN)
            finally:
                self._fh.close()
                self._fh = None


def _db_path() -> Path:
    return Path(_DATA_DIR) / _DB_FILE


def db_status() -> Dict[str, Any]:
    """Estado de la base NVD local: ready, size_mb, age_days, stale, updating."""
    p = _db_path()
    try:
        st = p.stat()
        size, age = st.st_size, (time.time() - st.st_mtime) / 86400
    except OSError:
        size, age = 0, None
    ready = size >= _MIN_DB_BYTES
    return {
        'ready':      ready,
        'size_mb':    round(size / (1024 * 1024), 1),
        'age_days':   round(age, 1) if age is not None else None,
        'stale':      bool(ready and age is not None and age > _STALE_AFTER_DAYS),
        'updating':   _update_state['running'],
        'last_error': _update_state['last_error'],
        'data_dir':   _DATA_DIR,
    }


def _update_database(nvd_api_key: Optional[str]) -> None:
    """Sincroniza la base NVD (lenta). Corre en un hilo; toma el candado de archivo."""
    lock = _FileLock(str(Path(_DATA_DIR) / '.depcheck.lock'))
    try:
        # No esperamos: si otro proceso ya está actualizando, no hace falta duplicarlo.
        if not lock.acquire(wait=0):
            logger.info("Dependency-Check: otra actualización de la base ya está en curso, se omite.")
            return
        os.makedirs(_DATA_DIR, exist_ok=True)
        cmd = [_BIN, '--updateonly', '--data', _DATA_DIR, '--disableVersionCheck']
        if nvd_api_key:
            cmd += ['--nvdApiKey', nvd_api_key]
        logger.info("Dependency-Check: sincronizando base NVD en %s ...", _DATA_DIR)
        code, stdout, stderr = _run_group(cmd, _UPDATE_TIMEOUT)
        if code != 0 or not db_status()['ready']:
            msg = (stderr or stdout or '').strip()[-400:] or f'código de salida {code}'
            _update_state['last_error'] = msg
            logger.warning("Dependency-Check: la actualización de la base falló — %s", msg)
        else:
            _update_state['last_error'] = None
            _update_state['last_ok'] = time.time()
            logger.info("Dependency-Check: base NVD lista (%s MB).", db_status()['size_mb'])
    except subprocess.TimeoutExpired:
        _update_state['last_error'] = f'La actualización de la base no terminó en {_UPDATE_TIMEOUT}s'
        logger.warning("Dependency-Check: %s", _update_state['last_error'])
    except Exception as e:  # noqa: BLE001 -- el hilo nunca debe morir en silencio
        _update_state['last_error'] = str(e)
        logger.exception("Dependency-Check: error inesperado actualizando la base")
    finally:
        lock.release()
        with _update_lock:
            _update_state['running'] = False


def ensure_database(nvd_api_key: Optional[str] = None, force: bool = False) -> bool:
    """
    Lanza la sincronización de la base NVD en un hilo si hace falta (base
    vacía o vieja). Devuelve True si arrancó una actualización ahora.
    Es seguro llamarlo muchas veces: no duplica trabajo.
    """
    if shutil.which(_BIN) is None:
        return False
    st = db_status()
    if not force and st['ready'] and not st['stale']:
        return False
    with _update_lock:
        if _update_state['running']:
            return False
        _update_state['running'] = True
        _update_state['started'] = time.time()
    threading.Thread(
        target=_update_database, args=(nvd_api_key or os.getenv('NVD_API_KEY'),),
        name='depcheck-db-update', daemon=True,
    ).start()
    return True


def _has_npm_manifest(root: Path) -> bool:
    """¿Hay package.json / lockfiles npm fuera de node_modules/.git? (recorrido acotado)"""
    names = {'package.json', 'package-lock.json', 'npm-shrinkwrap.json', 'yarn.lock', 'pnpm-lock.yaml'}
    for _dir, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if d not in ('node_modules', '.git')]
        if names.intersection(files):
            return True
    return False


class DependencyCheckScanner:
    """Wrapper del binario real de OWASP Dependency-Check."""

    def __init__(self, timeout: int = 600, nvd_api_key: Optional[str] = None):
        self.timeout     = timeout  # antes se ignoraba y se forzaba a 10800s
        self.nvd_api_key = nvd_api_key or os.getenv('NVD_API_KEY')
        # Node Audit consulta la API de npm por cada paquete del lockfile (RED, lento): por defecto
        # apagado. Sin él, Dependency-Check NO analiza package-lock.json (solo lista el archivo) --
        # en proyectos Node.js los CVE de dependencias los cubre Trivy. Actívalo con
        # DEPENDENCY_CHECK_NODE_AUDIT=true si quieres a Dependency-Check también sobre npm.
        self.node_audit  = os.getenv('DEPENDENCY_CHECK_NODE_AUDIT', 'false').strip().lower() == 'true'
        self.available   = shutil.which(_BIN) is not None
        if not self.available:
            logger.warning("Dependency-Check: el binario '%s' no está instalado en el servidor.", _BIN)
        if not self.nvd_api_key:
            logger.warning("Dependency-Check: sin NVD_API_KEY -- la sincronización de la base NVD es muy lenta "
                           "y puede ser rechazada por NVD. Configura NVD_API_KEY en .env.")

    def _result(self, status: str, findings=None, error: Optional[str] = None,
                warning: Optional[str] = None, **extra) -> Dict[str, Any]:
        out = {'findings': findings or [], 'error': error, 'warning': warning, 'status': status}
        out.update(extra)
        return out

    def scan(self, root_path: str) -> Dict[str, Any]:
        """
        Corre Dependency-Check contra `root_path` usando la base local (--noupdate).

        Returns:
            Dict con: findings (file, package, vuln_id, severity,
            cvss_score, description), error, warning, status
            ('completed'|'error'|'skipped'|'timeout'), dependencies_analyzed,
            db (estado de la base NVD).
        """
        root = Path(root_path)
        if not root.exists() or not root.is_dir():
            return self._result('error', error=f'Directorio no encontrado: {root_path}')

        if not self.available:
            return self._result('skipped', error='Dependency-Check no está instalado en el servidor')

        db = db_status()
        if not db['ready']:
            started = ensure_database(self.nvd_api_key)
            if db['updating'] or started:
                msg = ('La base de datos NVD todavía no está lista: se está sincronizando en segundo plano '
                       '(la primera vez tarda; mucho más rápido con NVD_API_KEY). Este análisis se omitió -- '
                       'NO significa que las dependencias estén libres de vulnerabilidades. Vuelve a escanear luego.')
            else:
                detail = f" Último error: {db['last_error']}" if db['last_error'] else ''
                msg = ('La base de datos NVD no está inicializada y no pudo sincronizarse.' + detail +
                       ' Configura NVD_API_KEY y reinicia el servicio (ver .env.example).')
            return self._result('skipped', error=msg, db=db)

        lock = _FileLock(str(Path(_DATA_DIR) / '.depcheck.lock'))
        if not lock.acquire(wait=_LOCK_WAIT):
            return self._result(
                'skipped', db=db,
                error=f'La base de Dependency-Check está en uso por otra operación (esperé {_LOCK_WAIT}s). '
                      'Se omitió este análisis; vuelve a intentarlo.')

        out_dir = tempfile.mkdtemp(prefix='depcheck-')
        started = time.monotonic()
        try:
            cmd = [
                _BIN,
                '-s', str(root),
                '-f', 'JSON',
                '-o', out_dir,
                '--data', _DATA_DIR,
                '--project', 'securescan-pro',
                '--disableVersionCheck',
                # La base se sincroniza APARTE (ensure_database); el scan nunca actualiza.
                '--noupdate',
                # Analizadores que hacen su PROPIA llamada de red por paquete y no
                # respetan --noupdate (se comían el timeout completo). Trivy ya cubre
                # esa parte; acá Dependency-Check trabaja solo contra la NVD local.
                '--disableRetireJs', '--disableOssIndex', '--disableCentral', '--disableHostedSuppressions',
            ]
            if not self.node_audit:
                cmd += ['--disableNodeAudit', '--disableYarnAudit']

            try:
                code, stdout, stderr = _run_group(cmd, self.timeout)
            except subprocess.TimeoutExpired:
                return self._result('timeout', db=db,
                                    error=f'Dependency-Check no terminó en {self.timeout}s '
                                          '(se mató el proceso completo para liberar la base de datos)')
            except FileNotFoundError:
                return self._result('skipped', error='Dependency-Check no está instalado en el servidor')

            report_path = Path(out_dir) / 'dependency-check-report.json'
            if not report_path.exists():
                msg = (stderr or stdout or '').strip()[-400:] or f'Dependency-Check no generó reporte (código {code})'
                logger.warning("Dependency-Check: %s", msg)
                return self._result('error', error=msg, db=db)

            try:
                data = json.loads(report_path.read_text(encoding='utf-8'))
            except ValueError as e:
                return self._result('error', error=f'Error parseando reporte de Dependency-Check: {e}', db=db)

            findings: List[Dict[str, Any]] = []
            deps = data.get('dependencies', []) or []
            for dep in deps:
                pkgs = dep.get('packages') or []
                pkg_id = pkgs[0].get('id') if pkgs and isinstance(pkgs[0], dict) else dep.get('fileName')
                for vuln in dep.get('vulnerabilities', []) or []:
                    cvss = vuln.get('cvssv3') or vuln.get('cvssv2') or {}
                    sev  = (vuln.get('severity') or cvss.get('baseSeverity') or 'unknown').lower()
                    # El puntaje CVSS manda: el campo 'severity' puede venir de otra fuente/versión
                    # (ej. CVSS 7.5 etiquetado "medium"). Escala CVSS v3: >=9 critical, >=7 high, >=4 medium.
                    try:
                        score = float(cvss.get('baseScore'))
                        sev = ('critical' if score >= 9 else 'high' if score >= 7
                               else 'medium' if score >= 4 else 'low' if score > 0 else sev)
                    except (TypeError, ValueError):
                        pass
                    findings.append({
                        'file':        dep.get('filePath') or dep.get('fileName'),
                        'package':     pkg_id or dep.get('fileName'),
                        'vuln_id':     vuln.get('name'),
                        'severity':    _SEVERITY_MAP.get(sev, 'unknown'),
                        'cvss_score':  cvss.get('baseScore'),
                        'description': (vuln.get('description') or '')[:250],
                    })

            warning = None
            if db['stale']:
                warning = (f"La base NVD tiene {db['age_days']} días: puede faltar información reciente. "
                           "Se está refrescando en segundo plano.")
            if not self.node_audit and _has_npm_manifest(root):
                npm_note = ("Este proyecto usa npm (package.json / package-lock.json): con Node Audit desactivado "
                            "Dependency-Check NO analiza esas dependencias, así que 'sin hallazgos' aquí no significa "
                            "que estén limpias. Consulta Trivy, que sí las cubre.")
                warning = f"{warning} {npm_note}" if warning else npm_note
            return self._result('completed', findings, warning=warning, db=db,
                                dependencies_analyzed=len(deps), node_audit=self.node_audit,
                                duration_s=round(time.monotonic() - started, 1))
        finally:
            lock.release()
            shutil.rmtree(out_dir, ignore_errors=True)
            if db.get('stale'):
                ensure_database(self.nvd_api_key)
