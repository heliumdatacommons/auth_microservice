from Crypto.Cipher import AES
import os

instance = None # singleton pointer, initialize Crypt() once if .crypt is None

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
        pad_n = (AES.block_size - (len(plaintext) % AES.block_size))
        plaintext += pad_n * chr(pad_n)

        iv = self.random(AES.block_size)
        aes = AES.new(self.key, AES.MODE_CFB, iv)
        encr = aes.encrypt(plaintext)
        enco = base64.b64encode(iv + encr)
        print("encrypted [{}] to [{}]".format(plaintext,enco))
        return enco
    
    def decrypt(self, ciphertext):
        de_enco = base64.b64decode(ciphertext)
        iv = de_enco[:AES.block_size]
        aes = AES.new(self.key, AES.MODE_CFB, iv)
        de_encr = aes.decrypt(de_enco[AES.block_size:])
        # unpad
        pad_n = de_encr[-1]
        de_encr = de_encr[:-ord(pad_n)]
        return de_encr
