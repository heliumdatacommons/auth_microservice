from django.test import TestCase, override_settings

from token_service.tests.app.util import create_fake_user
from token_service.models import (EncryptedTextField, User, Token, Scope,
                                  API_key, User_key, Nonce, PendingCallback,
                                  OIDCMetadataCache)

class ModelsTest(TestCase):
    def test_new_user(self):
        user = create_fake_user()
        self.assertEqual(user.user_name, 'john')
        self.assertEqual(user.name, 'doe')
        # name is encrypted text, getting the value should be decrypted
        # TODO: verify it's encrypted, and when it is read from DB it's decrypted
        #    -> current instance is not sufficient to show that

    def test_travis(self):
        # dummy test to validate travis
        self.assertEqual(1, 1)
