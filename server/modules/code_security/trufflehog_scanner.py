"""
TruffleHog Scanner (real)
Corre el binario real de TruffleHog vía subprocess — complementa a
Gitleaks con su diferencial real: VERIFICA en vivo si el secreto
encontrado todavía es válido, haciendo una llamada real a la API del
proveedor correspondiente (Stripe, AWS, GitHub, etc.).

Aviso importante de operación (no es un detalle menor): para verificar,
TruffleHog manda el secreto encontrado a la API real del proveedor. Esto
significa que si escaneas código de un tercero y tiene una credencial
real ahí, tu servidor va a "usar" esa credencial contra el servicio real
para confirmar si sigue activa -- éticamente esto solo debería hacerse
sobre código que tengas autorización de escanear (mismo principio que ya
aplica al resto de la plataforma), y puede quedar registrado del lado
del proveedor como un intento de acceso con esa credencial.

Escaneo de historial de git (confirmado con prueba real, mismo caso que
Gitleaks): si `root_path` tiene una carpeta `.git`, este módulo usa el
subcomando `trufflehog git file://<path>` (recorre todo el historial de
commits, con metadata limpia de commit/autor/fecha) en vez de
`trufflehog filesystem <path>`. Sin `.git` (ZIP subido), usa filesystem
como antes.

Formato de salida: `--json` de TruffleHog imprime un objeto JSON por
línea (JSON Lines), no un array -- se parsea línea por línea.
"""

import json
import logging
import shutil
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional

from modules.code_security.secret_utils import mask_secret

logger = logging.getLogger(__name__)

_BIN = 'trufflehog'


def _relativize(file_path: Any, root: Optional[Path]) -> Any:
    """
    TruffleHog (igual que Gitleaks) devuelve el path TAL COMO se le pasó el target: si `root_path`
    es absoluto (siempre lo es -- viene de un directorio temporal del propio servidor), el campo
    'file' del hallazgo queda con la ruta absoluta completa, filtrando la estructura interna del
    servidor (ej. '/tmp/codescan-<job>/code/...') -- y queda inconsistente con Semgrep/Backdoors/
    CryptoKeyScanner, que sí reportan rutas relativas al proyecto.
    """
    if not file_path or root is None:
        return file_path
    try:
        return str(Path(file_path).relative_to(root))
    except ValueError:
        return file_path  # ya era relativo (modo git) o fuera de root por algún link: se deja igual


def _parse_findings(stdout: str, root: Optional[Path] = None) -> List[Dict[str, Any]]:
    """Parsea la salida JSON Lines de TruffleHog (un objeto JSON por hallazgo)."""
    findings: List[Dict[str, Any]] = []
    for line in (stdout or '').splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            item = json.loads(line)
        except ValueError:
            continue  # línea de log que no es JSON de un hallazgo, se ignora
        if not isinstance(item, dict) or 'DetectorName' not in item:
            continue  # JSON de log/progreso, no un hallazgo

        secret = item.get('Raw', '') or ''
        masked = mask_secret(secret)
        source_data = (item.get('SourceMetadata') or {}).get('Data', {})
        git_meta = source_data.get('Git') or {}
        fs_meta  = source_data.get('Filesystem') or {}

        findings.append({
            'file':          _relativize(git_meta.get('file') or fs_meta.get('file'), root),
            'line':          git_meta.get('line') or fs_meta.get('line'),
            'detector':      item.get('DetectorName'),
            'description':   item.get('DetectorDescription'),
            'verified':      bool(item.get('Verified')),
            'secret_masked': masked,
            'severity':      'critical' if item.get('Verified') else 'high',  # verificado en vivo = credencial real y activa
            'commit':        git_meta.get('commit'),
            'author':        git_meta.get('email'),
            'date':          git_meta.get('timestamp'),
        })
    return findings


class TruffleHogScanner:
    """Wrapper del binario real de TruffleHog — detección + verificación en vivo de secretos."""

    def __init__(self, timeout: int = 120, verify: bool = True):
        self.timeout   = timeout
        self.verify    = verify  # False = más rápido, no llama a APIs de terceros
        self.available = shutil.which(_BIN) is not None
        if not self.available:
            logger.warning("TruffleHog: el binario '%s' no está instalado en el servidor.", _BIN)

    def scan(self, root_path: str) -> Dict[str, Any]:
        """
        Corre TruffleHog contra `root_path`. Si hay una carpeta .git
        (repo clonado), escanea todo el historial de commits vía el
        subcomando `git` -- si no (ZIP subido), usa `filesystem`.

        Returns:
            Dict con: findings (lista con file, line, detector,
            description, verified, secret_masked, commit, author, date),
            scanned_git_history (bool), error.
        """
        root = Path(root_path)
        if not root.exists() or not root.is_dir():
            return {'findings': [], 'scanned_git_history': False, 'error': f'Directorio no encontrado: {root_path}'}

        if not self.available:
            return {'findings': [], 'scanned_git_history': False, 'error': 'TruffleHog no está instalado en el servidor'}

        has_git = (root / '.git').is_dir()

        if has_git:
            cmd = [_BIN, 'git', f'file://{root}', '--json', '--no-update']
        else:
            cmd = [_BIN, 'filesystem', str(root), '--json', '--no-update']
        if not self.verify:
            cmd.append('--no-verification')

        timed_out = False
        try:
            result = subprocess.run(
                cmd,
                stdin=subprocess.DEVNULL,
                capture_output=True, text=True, timeout=self.timeout,
            )
            stdout, returncode, stderr = result.stdout or '', result.returncode, result.stderr or ''
        except subprocess.TimeoutExpired as e:
            # TruffleHog imprime un JSON por hallazgo A MEDIDA que avanza: lo encontrado antes del
            # timeout es válido y no se tira (en NodeGoat, 120s no alcanzaron para todo el historial).
            timed_out = True
            out = e.stdout or ''
            stdout = out.decode('utf-8', 'ignore') if isinstance(out, bytes) else out
            returncode, stderr = 0, ''
        except FileNotFoundError:
            return {'findings': [], 'scanned_git_history': has_git, 'status': 'skipped',
                    'error': 'TruffleHog no está instalado en el servidor'}

        findings = _parse_findings(stdout, root)
        verification = 'enabled' if self.verify else 'disabled'

        if timed_out:
            partial = (f' Se conservan {len(findings)} hallazgo(s) parcial(es).' if findings
                       else ' Sin hallazgos hasta ese momento; el análisis quedó incompleto.')
            return {'findings': findings, 'scanned_git_history': has_git, 'status': 'timeout',
                    'error': f'TruffleHog no terminó en {self.timeout}s.{partial} '
                             'Sube SCAN_TIMEOUT_TRUFFLEHOG o pon TRUFFLEHOG_VERIFY=false.',
                    'verification': verification}

        # Código != 0 sin hallazgos = fallo real (flag inválido, repo ilegible...), no "limpio".
        if returncode != 0 and not findings:
            detail = stderr.strip()[-400:] or f'código de salida {returncode}'
            logger.warning("TruffleHog falló: %s", detail)
            return {'findings': [], 'scanned_git_history': has_git, 'status': 'error',
                    'error': f'TruffleHog falló: {detail}'}

        return {'findings': findings, 'scanned_git_history': has_git, 'status': 'completed', 'error': None,
                'verification': verification}
