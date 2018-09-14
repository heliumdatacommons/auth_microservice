from django.test import TestCase, override_settings

from token_service.util import (generate_nonce, generate_base64, sanitize_base64,
                                list_subset, sha256, is_sock, build_redirect_url)


class UtilTest(TestCase):

    def test_travis(self):
        # dummy test to validate travis
        self.assertEqual(1, 1)
