from django.test import TestCase, override_settings

from token_service.config import admin_key, db_key, Config


class ConfigTest(TestCase):

    def test_travis(self):
        # dummy test to validate travis
        self.assertEqual(1, 1)
