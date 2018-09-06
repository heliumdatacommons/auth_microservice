from django.test import TestCase, override_settings

from token_service.apps import TokenServiceConfig


class AppsTest(TestCase):

    def test_travis(self):
        # dummy test to validate travis
        self.assertEqual(1, 1)
