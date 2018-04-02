from django.db import models
from . import crypt
import binascii

class EncryptedTextField(models.TextField):
    def __init__(self, *args, **kwargs):
        if crypt.instance == None:
            raise RuntimeError('crypt module not initialized')
        self.crypt = crypt.instance
        super().__init__(*args, **kwargs)

    # invoked to convert db value to python value
    def from_db_value(self, value, expression, connection):
        #print('EncryptedTextField.from_db_value value: ' + str(value))
        dec = self.crypt.decrypt(value)
        #print('EncryptedTextField.from_db_value({}) -> {}'.format(value, dec))
        return dec

    # invoked before saving python value to db value
    def get_prep_value(self, value):
        #print('EncryptedTextField.get_prep_value value: ' + str(value))
        enc = self.crypt.encrypt(value)
        #print('EncryptedTextField.get_prep_value({}) -> {}'.format(value, enc))
        return enc

class User(models.Model):
    id = models.CharField(primary_key=True, max_length=256)
    user_name = models.CharField(max_length=256)

class Token(models.Model):
    user = models.ForeignKey('User', on_delete=models.CASCADE)
    access_token = EncryptedTextField() # unknown size
    refresh_token = EncryptedTextField() # unknown size
    expires = models.DateTimeField()
    provider = models.CharField(max_length=256)
    issuer = models.CharField(max_length=256)
    enabled = models.BooleanField(default=True)
    scopes = models.ManyToManyField('Scope')
    nonce = models.CharField(max_length=256)

class Scope(models.Model):
    name = models.CharField(max_length=256)

class API_key(models.Model):
    key = EncryptedTextField() # the key
    owner = EncryptedTextField() # short string describing what this api key is used for/by
    enabled = models.BooleanField(default=True)
