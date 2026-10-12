"""
Custodia TEMPORAL del material criptográfico encontrado.

Por qué existe: el directorio del código se borra al terminar el análisis, pero la
inspección completa se pide DESPUÉS y a demanda. En vez de dejar los archivos en
disco o meter los secretos en el historial del análisis, los bytes de cada llave
se guardan cifrados (Fernet) en Redis con caducidad, aparte del registro del scan.

  - Se necesita CODE_SCAN_VAULT_KEY (clave Fernet compartida entre api y worker).
    Sin ella la custodia queda DESACTIVADA: el análisis público sigue funcionando,
    pero no se puede inspeccionar en detalle.
  - Caducidad: CODE_SCAN_VAULT_TTL (segundos, por defecto 3600).
  - Nunca se registra el contenido ni la clave.
  - Si Redis no está disponible se usa un diccionario en memoria del proceso: solo
    sirve cuando API y worker son el mismo proceso (modo desarrollo con hilos).

Generar una clave:
    python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
"""

import logging
import os
import threading
import time
from typing import Callable, Dict, Optional, Tuple

logger = logging.getLogger(__name__)

DEFAULT_TTL = 3600


class Vault:
    def __init__(self, redis_getter: Callable[[], Optional[object]], key: Optional[str] = None,
                 ttl: Optional[int] = None):
        self._redis_getter = redis_getter
        self.ttl = int(ttl if ttl is not None else os.environ.get('CODE_SCAN_VAULT_TTL', DEFAULT_TTL))
        self._fernet = None
        self._mem: Dict[str, Tuple[float, bytes]] = {}
        self._lock = threading.Lock()
        raw_key = key if key is not None else os.environ.get('CODE_SCAN_VAULT_KEY', '')
        if raw_key:
            try:
                from cryptography.fernet import Fernet
                self._fernet = Fernet(raw_key.encode() if isinstance(raw_key, str) else raw_key)
            except Exception:  # noqa: BLE001 -- jamás se imprime la clave
                logger.warning("CODE_SCAN_VAULT_KEY inválida: la custodia de llaves queda desactivada")

    @property
    def enabled(self) -> bool:
        return self._fernet is not None

    @staticmethod
    def _k(scan_id: str, item_id: str) -> str:
        return f'cryptovault:{scan_id}:{item_id}'

    def put(self, scan_id: str, item_id: str, data: bytes) -> bool:
        if not self.enabled:
            return False
        token = self._fernet.encrypt(data)
        r = self._redis_getter()
        if r is not None:
            try:
                r.setex(self._k(scan_id, item_id), self.ttl, token)
                return True
            except Exception:  # noqa: BLE001
                logger.warning("Vault: Redis no disponible, se usa memoria del proceso")
        with self._lock:
            self._purge_locked()
            self._mem[self._k(scan_id, item_id)] = (time.monotonic() + self.ttl, token)
        return True

    def get(self, scan_id: str, item_id: str) -> Optional[bytes]:
        if not self.enabled:
            return None
        token = None
        r = self._redis_getter()
        if r is not None:
            try:
                token = r.get(self._k(scan_id, item_id))
            except Exception:  # noqa: BLE001
                token = None
        if token is None:
            with self._lock:
                self._purge_locked()
                entry = self._mem.get(self._k(scan_id, item_id))
                token = entry[1] if entry else None
        if token is None:
            return None
        try:
            return self._fernet.decrypt(token if isinstance(token, bytes) else token.encode())
        except Exception:  # noqa: BLE001
            return None

    def _purge_locked(self) -> None:
        now = time.monotonic()
        for k in [k for k, (exp, _) in self._mem.items() if exp < now]:
            self._mem.pop(k, None)
