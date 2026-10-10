#!/usr/bin/env python3
"""
Consolida las reglas de seguridad del repo público semgrep/semgrep-rules en
una carpeta plana (un solo --config es mucho más rápido en runtime).

BUG que corrige: el one-liner original del Dockerfile usaba el glob
`<lang>/**/security/*.yaml`, que solo toma archivos DIRECTAMENTE dentro de
una carpeta `security` y se pierde todas las subcarpetas (`security/injection`,
`security/audit`...). En la práctica quedaban ~34 de 64 reglas de PHP --
entre las perdidas, `tainted-sql-string` (inyección SQL). Además el nombre
de destino usaba solo el basename, así que reglas con el mismo nombre en
carpetas distintas se pisaban entre sí.

Ahora: recorre TODO el árbol, conserva reglas dentro de cualquier carpeta
`security`, ignora los fixtures `*.test.yaml`, y usa la ruta relativa
completa (con "__") como nombre de destino para evitar colisiones.

Uso: consolidate_semgrep_rules.py <repo_clonado> <destino> [min_reglas]
"""
import glob
import os
import shutil
import sys

LANGS = ['php', 'python', 'javascript', 'typescript', 'java', 'go', 'ruby', 'csharp', 'dockerfile']


def consolidate(src: str, dst: str) -> int:
    os.makedirs(dst, exist_ok=True)
    count = 0
    for lang in LANGS:
        for f in glob.glob(os.path.join(src, lang, '**', '*.y*ml'), recursive=True):
            rel = os.path.relpath(f, src)
            parts = rel.split(os.sep)
            if '.test.' in parts[-1] or 'security' not in parts[:-1]:
                continue
            shutil.copy(f, os.path.join(dst, '__'.join(parts)))
            count += 1
    return count


if __name__ == '__main__':
    src, dst = sys.argv[1], sys.argv[2]
    minimum = int(sys.argv[3]) if len(sys.argv) > 3 else 0
    n = consolidate(src, dst)
    print(f'semgrep: {n} reglas consolidadas en {dst}')
    if n < minimum:
        sys.exit(f'ERROR: se esperaban al menos {minimum} reglas y solo hay {n}')
