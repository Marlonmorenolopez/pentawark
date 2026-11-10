"""
Detección de candidatos a material criptográfico DENTRO del árbol de archivos.

La detección es por CONTENIDO (marcadores PEM, líneas de llave pública OpenSSH
y estructura DER válida), no por nombre ni extensión. Es lectura pura: nada se
ejecuta ni se abre fuera del directorio analizado, y los enlaces simbólicos se
ignoran. Está acotada en tamaño de archivo, cantidad de archivos y tiempo.
"""

import hashlib
import os
import re
import time
from dataclasses import dataclass
from typing import Iterator, List, Optional, Tuple

from modules.code_security.crypto_inspector.analyze import label_is_crypto

MAX_FILE_BYTES = 64 * 1024        # una llave/certificado típico pesa < 10 KB
MAX_FILES_VISITED = 50_000
MAX_CANDIDATES = 300
MAX_SECONDS = 120

_PEM_RE = re.compile(rb'-----BEGIN ([A-Z0-9 ]{3,40})-----(.{0,65000}?)-----END \1-----', re.S)
_SSH_PUB_RE = re.compile(
    rb'^(ssh-rsa|ssh-dss|ssh-ed25519|ecdsa-sha2-nistp(?:256|384|521))[ \t]+[A-Za-z0-9+/=]{20,}(?:[ \t][^\r\n]*)?$',
    re.M)


@dataclass
class Candidate:
    rel_path: str
    line: int
    fmt: str                  # 'PEM' | 'DER' | 'OPENSSH_PUB'
    label: Optional[str]      # etiqueta PEM
    raw: bytes                # bloque exacto (PEM/línea) o archivo completo (DER)
    index: int                # posición del bloque dentro del archivo

    @property
    def item_id(self) -> str:
        h = hashlib.sha256(self.raw).hexdigest()
        return hashlib.sha256(f'{self.rel_path}|{self.index}|{h}'.encode()).hexdigest()[:16]


def der_total_length(data: bytes) -> Optional[int]:
    """Largo total de un SEQUENCE DER bien formado en `data`, o None si no lo es."""
    if len(data) < 32 or data[0] != 0x30:
        return None
    b1 = data[1]
    if b1 < 0x80:
        return 2 + b1
    n = b1 & 0x7F
    if n == 0 or n > 3 or len(data) < 2 + n:
        return None
    return 2 + n + int.from_bytes(data[2:2 + n], 'big')


def _line_of(data: bytes, offset: int) -> int:
    return data.count(b'\n', 0, offset) + 1


def extract_candidates(rel_path: str, data: bytes) -> List[Candidate]:
    """Candidatos presentes en el contenido de UN archivo."""
    out: List[Candidate] = []
    idx = 0
    for m in _PEM_RE.finditer(data):
        label = m.group(1).decode('ascii', 'replace')
        if not label_is_crypto(label):
            continue
        out.append(Candidate(rel_path, _line_of(data, m.start()), 'PEM', label, m.group(0), idx))
        idx += 1
    for m in _SSH_PUB_RE.finditer(data):
        out.append(Candidate(rel_path, _line_of(data, m.start()), 'OPENSSH_PUB', None, m.group(0).strip(), idx))
        idx += 1
    if not out and der_total_length(data) == len(data):
        out.append(Candidate(rel_path, 1, 'DER', None, data, 0))
    return out


def walk_candidates(root: str) -> Tuple[List[Candidate], dict]:
    """Recorre `root` y devuelve (candidatos, estadísticas de recorrido)."""
    stats = {'files_visited': 0, 'files_read': 0, 'truncated': None}
    found: List[Candidate] = []
    started = time.monotonic()
    root = os.path.abspath(root)

    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = [d for d in dirnames if d != '.git']
        for name in filenames:
            stats['files_visited'] += 1
            if stats['files_visited'] > MAX_FILES_VISITED:
                stats['truncated'] = 'files'
                return found, stats
            if time.monotonic() - started > MAX_SECONDS:
                stats['truncated'] = 'time'
                return found, stats
            path = os.path.join(dirpath, name)
            try:
                if os.path.islink(path) or not os.path.isfile(path):
                    continue
                size = os.path.getsize(path)
                if size < 20 or size > MAX_FILE_BYTES:
                    continue
                with open(path, 'rb') as fh:
                    data = fh.read(MAX_FILE_BYTES + 1)
            except OSError:
                continue  # permisos / archivo desaparecido: se omite, no se aborta
            stats['files_read'] += 1
            rel = os.path.relpath(path, root).replace(os.sep, '/')
            for cand in extract_candidates(rel, data):
                found.append(cand)
                if len(found) >= MAX_CANDIDATES:
                    stats['truncated'] = 'candidates'
                    return found, stats
    return found, stats
