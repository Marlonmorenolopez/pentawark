import sys
from pathlib import Path

BASE = Path(__file__).resolve().parent / "server"
changes_applied = 0
changes_skipped = 0

def patch(file_path, old, new, label):
    global changes_applied, changes_skipped
    full_path = BASE / file_path
    if not full_path.exists():
        print(f"[OMITIDO] {label}: no se encontro el archivo {full_path}")
        changes_skipped += 1
        return
    text = full_path.read_text(encoding="utf-8")
    count = text.count(old)
    if count == 0:
        print(f"[OMITIDO] {label}: el texto esperado no aparece en {file_path}")
        changes_skipped += 1
        return
    if count > 1:
        print(f"[OMITIDO] {label}: el texto aparece {count} veces en {file_path}, no es seguro")
        changes_skipped += 1
        return
    full_path.write_text(text.replace(old, new), encoding="utf-8")
    print(f"[OK] {label}")
    changes_applied += 1

patch(
    "modules/pentesting/orchestrator.py",
    old="return [{'error': f\"Nuclei timeout after {self.TIMEOUTS['nuclei']}s\", 'tool': 'nuclei'}]",
    new="return [{'error': f\"Nuclei timeout after {self.TIMEOUTS['nuclei']}s\", 'tool': 'nuclei', 'simulated': True}]",
    label="A2 - Nuclei: timeout marcado como simulated",
)

patch(
    "modules/pentesting/orchestrator.py",
    old="return [{'error': f\"Patator timeout after {self.TIMEOUTS['patator']}s\", 'tool': 'patator'}]",
    new="return [{'error': f\"Patator timeout after {self.TIMEOUTS['patator']}s\", 'tool': 'patator', 'simulated': True}]",
    label="A2 - Patator: timeout marcado como simulated",
)

old_detect = '''    def _detect_login_path(self, target: str) -> str:
        parsed = urlparse(target)
        base   = f"{parsed.scheme}://{parsed.hostname}"
        if parsed.port:
            base += f":{parsed.port}"
        for path in _LOGIN_PATHS:'''

new_detect = '''    _KNOWN_LOGIN_PATHS = {
        'testfire': '/bank/login',
        'dvwa':     '/login.php',
        'webgoat':  '/WebGoat/login',
        'juice':    '/rest/user/login',
    }

    def _detect_login_path(self, target: str) -> str:
        t = target.lower()
        for key, known_path in self._KNOWN_LOGIN_PATHS.items():
            if key in t:
                logger.info("Login path conocido para '%s': %s", key, known_path)
                return known_path

        parsed = urlparse(target)
        base   = f"{parsed.scheme}://{parsed.hostname}"
        if parsed.port:
            base += f":{parsed.port}"
        for path in _LOGIN_PATHS:'''

patch(
    "modules/pentesting/orchestrator.py",
    old=old_detect,
    new=new_detect,
    label="A3 - Patator: rutas de login reales por laboratorio",
)

patch(
    "modules/pentesting/ffuf.py",
    old="""                '-mc', '200,201,301,302,401,403',
                '-fc', '404',
                '-s',                   # Modo silencioso""",
    new="""                '-mc', '200,201,301,302,401,403',
                '-fc', '404',
                '-ac',
                '-s',                   # Modo silencioso""",
    label="A4 - ffuf: auto-calibracion contra falsos positivos",
)

print()
print(f"Aplicados: {changes_applied}  |  Omitidos: {changes_skipped}")
