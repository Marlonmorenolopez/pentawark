"""
Seguimiento del estado de remediación de un Finding (sección 8.6-8.7 de la
auditoría de Pentesting).

Antes de este módulo, un hallazgo no tenía ningún estado de remediación:
aparecía en la UI mientras el scan existiera y desaparecía con él. No había
forma de marcar "en remediación", de distinguir una declaración del usuario
("ya lo corregí") de una verificación técnica real, ni de reabrir un
hallazgo que reaparece en un scan posterior.

Diseño (igual criterio "fail-open" que modules/common/circuit_breaker.py,
que ya es Redis-backed con fallback en memoria): el estado persiste en
Redis, clave por finding_id (el fingerprint estable de 16 hex que ya
genera findings.py — ESTABLE entre distintos scans del mismo target/tool/
título, que es justo lo que se necesita para dar seguimiento a un hallazgo
a través del tiempo). Si Redis no está disponible, cae a un dict en
memoria del proceso (se pierde al reiniciar, pero no rompe la funcionalidad).

Máquina de estados:
    pending -> in_remediation -> fixed_pending_verification -> verified
                                                              -> reopened (si la reverificación falla)
    reopened -> pending (vuelve a quedar como pendiente de corrección)

Regla central (criterio de aceptación #8 del encargo): 'verified' y
'reopened' NUNCA se alcanzan por una declaración del usuario vía
set_status() -- solo por record_verification(), que exige evidencia de una
comprobación real. set_status() solo mueve entre pending/in_remediation/
fixed_pending_verification.
"""

import json
import logging
import threading
import time
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


# Estados declarables por el usuario (una afirmación, no una verificación).
USER_SETTABLE_STATUSES = ('pending', 'in_remediation', 'fixed_pending_verification')

# Estados alcanzables solo mediante una verificación técnica real.
VERIFICATION_STATUSES = ('verified', 'reopened')

ALL_STATUSES = USER_SETTABLE_STATUSES + VERIFICATION_STATUSES

DEFAULT_STATUS = 'pending'

_TTL_SECONDS = 60 * 60 * 24 * 90  # 90 días — un hallazgo puede tardar en remediarse


class InvalidTransition(ValueError):
    pass


class RemediationStore:
    def __init__(self, redis_client=None, key_prefix: str = 'remediation'):
        self.redis = redis_client
        self.key_prefix = key_prefix
        self._fallback: Dict[str, Dict[str, Any]] = {}
        self._lock = threading.Lock()

    def _key(self, finding_id: str) -> str:
        return f'{self.key_prefix}:{finding_id}'

    # ── Lectura ──────────────────────────────────────────────────────────────

    def get(self, finding_id: str) -> Dict[str, Any]:
        raw = None
        if self.redis is not None:
            try:
                raw = self.redis.get(self._key(finding_id))
            except Exception as e:
                logger.warning("RemediationStore: Redis no disponible al leer -- %s", e)

        if raw is None:
            with self._lock:
                record = self._fallback.get(finding_id)
                if record is not None:
                    return dict(record)
            return {'finding_id': finding_id, 'status': DEFAULT_STATUS, 'history': []}

        try:
            data = json.loads(raw)
            data.setdefault('finding_id', finding_id)
            data.setdefault('status', DEFAULT_STATUS)
            data.setdefault('history', [])
            return data
        except ValueError:
            return {'finding_id': finding_id, 'status': DEFAULT_STATUS, 'history': []}

    def get_many(self, finding_ids: List[str]) -> Dict[str, Dict[str, Any]]:
        return {fid: self.get(fid) for fid in finding_ids}

    # ── Escritura ────────────────────────────────────────────────────────────

    def _save(self, finding_id: str, record: Dict[str, Any]) -> None:
        if self.redis is not None:
            try:
                self.redis.setex(self._key(finding_id), _TTL_SECONDS, json.dumps(record))
                return
            except Exception as e:
                logger.warning("RemediationStore: Redis no disponible al escribir -- %s", e)
        with self._lock:
            self._fallback[finding_id] = record

    def _append_history(self, record: Dict[str, Any], from_status: str, to_status: str,
                         entry_type: str, comment: str = '', actor: Optional[str] = None,
                         evidence: Optional[Dict[str, Any]] = None) -> None:
        record.setdefault('history', []).append({
            'timestamp':   time.time(),
            'type':        entry_type,       # 'user_declaration' | 'verification'
            'from_status': from_status,
            'to_status':   to_status,
            'comment':     comment or '',
            'actor':       actor,
            'evidence':    evidence,
        })

    def set_status(self, finding_id: str, new_status: str, comment: str = '',
                    actor: Optional[str] = None) -> Dict[str, Any]:
        """
        Declaración del usuario (ej. "ya apliqué la corrección"). Solo puede
        mover el hallazgo entre pending / in_remediation /
        fixed_pending_verification -- NUNCA a 'verified' ni 'reopened'
        (ver record_verification para eso). Esta distinción es intencional:
        el encargo exige que "una declaración del usuario no se confunda
        con una verificación técnica".
        """
        if new_status not in USER_SETTABLE_STATUSES:
            raise InvalidTransition(
                f"'{new_status}' no puede establecerse manualmente -- solo mediante una "
                f"verificación técnica real (ver record_verification). Estados permitidos "
                f"aquí: {USER_SETTABLE_STATUSES}."
            )
        record = self.get(finding_id)
        old_status = record.get('status', DEFAULT_STATUS)
        record['status'] = new_status
        self._append_history(record, old_status, new_status, 'user_declaration', comment, actor)
        self._save(finding_id, record)
        return record

    def record_verification(self, finding_id: str, persists: bool, evidence: Dict[str, Any],
                             comment: str = '', actor: Optional[str] = None) -> Dict[str, Any]:
        """
        Resultado de una comprobación técnica real (re-ejecución de la
        verificación correspondiente al tipo de hallazgo). `persists` debe
        reflejar un resultado concluyente -- si la comprobación no pudo
        completarse (herramienta no disponible, objetivo inalcanzable),
        esta función NO debe llamarse con un resultado inventado; el
        llamador debe dejar el hallazgo en su estado actual y explicarlo
        (ver record_inconclusive_verification).
        """
        record = self.get(finding_id)
        old_status = record.get('status', DEFAULT_STATUS)
        new_status = 'reopened' if persists else 'verified'
        record['status'] = new_status
        record['last_verification'] = {
            'timestamp': time.time(), 'persists': persists, 'evidence': evidence,
        }
        self._append_history(record, old_status, new_status, 'verification', comment, actor, evidence)
        self._save(finding_id, record)
        return record

    def record_inconclusive_verification(self, finding_id: str, reason: str,
                                          actor: Optional[str] = None) -> Dict[str, Any]:
        """
        La comprobación se intentó pero no fue concluyente (herramienta no
        disponible, objetivo inalcanzable, timeout). El estado NO cambia --
        solo se deja constancia en el historial de que se intentó y por qué
        no se pudo concluir. Evita el error que el encargo pide prevenir
        explícitamente: "una prueba fallida o incompleta no debe marcar una
        vulnerabilidad como corregida".
        """
        record = self.get(finding_id)
        status = record.get('status', DEFAULT_STATUS)
        self._append_history(
            record, status, status, 'verification_inconclusive',
            comment=reason, actor=actor,
        )
        self._save(finding_id, record)
        return record

    def reopen_from_recurrence(self, finding_id: str, scan_id: str,
                                actor: Optional[str] = None) -> Dict[str, Any]:
        """
        Atajo para cuando un hallazgo con el MISMO fingerprint vuelve a
        aparecer en un scan nuevo sobre un finding que estaba 'verified'.
        Esto SÍ es evidencia real (el propio scan lo volvió a detectar), a
        diferencia de una declaración del usuario.
        """
        record = self.get(finding_id)
        if record.get('status') != 'verified':
            # Si no estaba verificado, reaparecer en un scan nuevo no es una
            # "reapertura" -- simplemente sigue pendiente/sin cambios.
            return record
        return self.record_verification(
            finding_id, persists=True,
            evidence={'reason': 'recurrence_in_new_scan', 'scan_id': scan_id},
            comment='El hallazgo reapareció en un análisis posterior tras haber sido verificado como corregido.',
            actor=actor,
        )
