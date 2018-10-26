from django.test import TestCase, override_settings

from token_service.crypt import Crypt


class CryptTest(TestCase):

    def test_travis(self):
        # dummy test to validate travis
        self.assertEqual(1, 1)

    def test_inst(self):
        cr = Crypt('1' * 32)
        msg = 'abc'
        enc = cr.encrypt(msg)
        dec = cr.decrypt(enc)
        self.assertEqual(dec, msg)
