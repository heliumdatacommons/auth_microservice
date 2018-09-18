import base64
import os
from Crypto.Cipher import AES
from token_service.util import logging_sensitive

instance = None  # singleton pointer, initialize Crypt() once if .crypt is None


class Crypt(object):
    inst = None
    algo = AES

    def __init__(self, key):
        self.key = key
        self.random = os.urandom
        global crypt
        crypt = self

    def encrypt(self, plaintext):
        # pad PKSC#7 (https://www.ietf.org/rfc/rfc2315.txt)
        if plaintext:
            pad_n = (AES.block_size - (len(plaintext) % AES.block_size))
        else:
            plaintext = ''
            pad_n = AES.block_size

        plaintext += pad_n * chr(pad_n)

        logging_sensitive('crypt.encrypt plaintext: %s', plaintext)

        iv = self.random(AES.block_size)
        logging_sensitive('crypt.encrypt iv: %s', iv)

        aes = AES.new(self.key, AES.MODE_CFB, iv)
        encr = aes.encrypt(plaintext)
        enco = base64.b64encode(iv + encr)
        enco = enco.decode('utf-8')
        logging_sensitive("encrypted [%s] to [%s]", plaintext, enco)
        return enco

    def decrypt(self, ciphertext):
        logging_sensitive('crypt.decrypt ciphertext: %s', ciphertext)
        if len(ciphertext) % 4 != 0:
            ciphertext += '=' * (4 - (len(ciphertext) % 4))
        de_enco = base64.b64decode(ciphertext)
        iv = de_enco[:AES.block_size]
        aes = AES.new(self.key, AES.MODE_CFB, iv)
        de_encr = aes.decrypt(de_enco[AES.block_size:])
        logging_sensitive('crypt.decrypt de_encr: %s', de_encr)
        # unpad
        pad_n = ord(de_encr[-1])
        de_encr = de_encr[:-pad_n]
        de_encr = de_encr.decode('utf-8')
        logging_sensitive('crypt.decrypt de_encr unpad: %s', de_encr)
        return de_encr
