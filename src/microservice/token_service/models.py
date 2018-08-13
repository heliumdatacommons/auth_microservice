from django.db import models
from . import crypt
import binascii

'''
Arbitrary length encrypted text field using token_service.crypt module
'''
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
    name = EncryptedTextField()

'''
OpenID Connect/OAuth 2.0 token information
'''
class Token(models.Model):
    user = models.ForeignKey('User', on_delete=models.CASCADE)
    access_token = EncryptedTextField() # unknown size
    refresh_token = EncryptedTextField() # unknown size
    expires = models.DateTimeField()
    provider = models.CharField(max_length=256)
    issuer = models.CharField(max_length=256)
    enabled = models.BooleanField(default=True)
    scopes = models.ManyToManyField('Scope')
    nonce = models.ManyToManyField('Nonce')
    access_token_hash = models.TextField()

class Scope(models.Model):
    name = models.CharField(max_length=256) # arbitrary but unlikely to be exceeded

'''
Keys generated for client applications
'''
class API_key(models.Model):
    key_hash = models.CharField(max_length=256) # the sha256 of the api key
    owner = EncryptedTextField() # short string describing what this api key is used for/by
    enabled = models.BooleanField(default=True)

'''
Keys generated for users
'''
class User_key(models.Model):
    id = models.CharField(primary_key=True, max_length=256)
    key_hash = models.CharField(max_length=256)
    label = models.CharField(max_length=256, null=True, blank=True)
    creation_time = models.DateTimeField(auto_now_add=True)
    user = models.ForeignKey('User', on_delete=models.CASCADE)

'''
Nonces used for req/resp exchanges and auth flows
'''
class Nonce(models.Model):
    value = models.TextField() # TODO encrypt this
    creation_time = models.DateTimeField(auto_now_add=True)

'''
Used for sharing state between processes because python can't run real threads
'''
class PendingCallback(models.Model):
    uid = models.CharField(max_length=256) # same type as User.id
    state = EncryptedTextField()
    nonce = EncryptedTextField()
    scopes = models.ManyToManyField('Scope')
    provider = models.CharField(max_length=256) # config.json must limit
    url = EncryptedTextField()
    return_to = EncryptedTextField()
    creation_time = models.DateTimeField(auto_now_add=True)

# TODO remove, obsolete
#class BlockingRequest(models.Model):
#    uid = models.CharField(max_length=256) # same type as User.id
#    nonce = EncryptedTextField()
#    scopes = models.ManyToManyField('Scope')
#    provider = models.CharField(max_length=256)
#    socket_file = models.CharField(max_length=256) # path to socket file
#    creation_time = models.DateTimeField(auto_now_add=True)

'''
Used for caching OpenID Connect provider metadata. It does not change often and is refreshed after an expiration period
'''
class OIDCMetadataCache(models.Model):
    value = models.TextField() # arbitrary length. careful about what is under metadata_url in config.json, could DoS
    retrieval_time = models.DateTimeField(auto_now_add=True)
    provider = models.CharField(max_length=256)

