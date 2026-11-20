from pathlib import Path

p = Path("server/modules/pentesting/nuclei.py")
text = p.read_text(encoding="utf-8")

old = """        # -as si nuclei >= 2.9 (WARN-01 FIX)
        try:
            maj, mino, _ = (int(x) for x in self._nuclei_ver.split('.')[:3])
            if (maj, mino) >= (2, 9):
                cmd += ['-as']
        except Exception:
            pass"""

new = """        # -as DESACTIVADO (auditoria pentesting, grupo A2b): el flag -as
        # (automatic scan / tech-detect) provoca un panic/crash (SIGSEGV) en
        # nuclei v3.2.4 dentro de automaticscan.go, que termina en returncode=2
        # y 0 hallazgos. Como el comando ya pasa -tags explicitos, -as es
        # redundante ademas de estar roto en esta version. Si se actualiza
        # nuclei a una version donde este bug este corregido, se puede
        # reactivar."""

count = text.count(old)
if count == 1:
    p.write_text(text.replace(old, new), encoding="utf-8")
    print("[OK] A2b - Nuclei: flag -as desactivado (evita el crash SIGSEGV)")
elif count == 0:
    print("[OMITIDO] No se encontro el texto esperado (¿ya esta aplicado?)")
else:
    print(f"[OMITIDO] El texto aparece {count} veces, no es seguro reemplazar")
