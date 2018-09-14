from django.test import TestCase, override_settings

from token_service.views import isint


class ViewsTest(TestCase):

    def test_travis(self):
        # dummy test to validate travis
        self.assertEqual(1, 1)
