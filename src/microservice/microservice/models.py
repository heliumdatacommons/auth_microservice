from django.db import models
from microservice import crypt

class EncryptedTextField(models.TextField):
    def __init__(self, *args, **kwargs):
        if crypt.instance == None:
            raise RuntimeError('crypt module not initialized')
        self.crypt = crypt.instance
        super().__init__(*args, **kwargs)

    # invoked to convert db value to python value
    def from_db_value(self, value):
        dec = self.crypt.decrypt(value)
        return dec

    # invoked before saving python value to db value
    def get_prep_value(self, value):
        enc = self.crypt.encrypt(value)
        return enc

class User(models.Model):
    user_id = models.CharField(max_length=256)
    user_name = models.CharField(max_length=256)

class Token(models.Model):
    token_id = models.IntegerField(primary_key=True)
    user_id = models.ForeignKey('User', on_delete=models.CASCADE)
    access_token = EncryptedTextField() # unknown size
    refresh_token = EncryptedTextField() # unknown size
    expires = models.DateTimeField()
    provider = models.CharField(max_length=256)
    issuer = models.CharField(max_length=256)
    enabled = models.BooleanField(default=True)

class Scope(models.Model):
    name = models.CharField(max_length=256)

class API_key(models.Model):
    key = models.CharField(max_length=256)
