"""
Pruebas unitarias para server/utils/scoring.py::generate_recommendations

Contexto (auditoría de cobertura de vulnerabilidades, 2026-11, Fase 0 #4,
hallazgo de la sección 7 de la auditoría de solo lectura): se evaluó
enmascarar la contraseña real encontrada por Patator antes de insertarla
en la recomendación de "credenciales débiles" (ver AUDIT_PENTESTING.md
§6.10), por higiene de evidencias en reportes exportados.

DECISIÓN DEL USUARIO (2026-11-06): mantener la contraseña en texto plano.
Son credenciales de los laboratorios propios del proyecto (DVWA/Juice
Shop/WebGoat), no secretos de producción, y el objetivo académico del
reporte es mostrar exactamente qué credencial débil encontró Patator.
Estas pruebas fijan ese comportamiento explícito: el texto plano
("admin/password") debe aparecer en la recomendación, no una versión
enmascarada.

Ejecutar:
    cd server && python3 -m unittest tests.test_scoring_recommendations -v
"""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))  # server/

from utils.scoring import generate_recommendations  # noqa: E402


class TestWeakCredentialsRecommendationShowsPlainTextPassword(unittest.TestCase):
    """Decisión explícita del usuario: la contraseña real debe verse tal
    cual en el reporte, no enmascarada."""

    def test_password_appears_in_plain_text(self):
        creds = [{'username': 'admin', 'password': 'password'}]
        recs = generate_recommendations({'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}, [], creds)
        joined = ' '.join(recs)
        self.assertIn('admin/password', joined)

    def test_username_and_password_both_present(self):
        creds = [{'username': 'admin', 'password': 'secret123'}]
        recs = generate_recommendations({'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}, [], creds)
        joined = ' '.join(recs)
        self.assertIn('admin/secret123', joined)
        self.assertNotIn('*', joined)

    def test_up_to_three_credentials_included_in_plain_text(self):
        creds = [
            {'username': 'admin', 'password': 'aaaa'},
            {'username': 'root', 'password': 'bb'},
            {'username': 'test', 'password': 'c'},
            {'username': 'fourth', 'password': 'ddddd'},
        ]
        recs = generate_recommendations({'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}, [], creds)
        joined = ' '.join(recs)
        self.assertIn('admin/aaaa', joined)
        self.assertIn('root/bb', joined)
        self.assertIn('test/c', joined)
        self.assertNotIn('fourth/', joined)

    def test_empty_password_does_not_crash(self):
        creds = [{'username': 'admin', 'password': ''}]
        recs = generate_recommendations({'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}, [], creds)
        joined = ' '.join(recs)
        self.assertIn('admin/', joined)

    def test_no_credentials_produces_no_credentials_recommendation(self):
        recs = generate_recommendations({'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}, [], None)
        joined = ' '.join(recs)
        self.assertNotIn('/', joined.split('CRÍTICO')[-1] if 'CRÍTICO' in joined else '')


if __name__ == '__main__':
    unittest.main()
