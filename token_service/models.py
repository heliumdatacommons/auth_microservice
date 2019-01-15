from django.db import models
from . import crypt
from token_service.util import logging_sensitive


class EncryptedTextField(models.TextField):
    '''
    Arbitrary length encrypted text field using token_service.crypt module
    '''
    def __init__(self, *args, **kwargs):
        if crypt.instance is None:
            raise RuntimeError('crypt module not initialized')
        self.crypt = crypt.instance
        super(EncryptedTextField, self).__init__(*args, **kwargs)

    # invoked to convert db value to python value
    #    context: not used as from django 2.0
    def from_db_value(self, value, expression, connection, context):
        logging_sensitive('EncryptedTextField.from_db_value value: %s', value)
        dec = self.crypt.decrypt(value)
        logging_sensitive('EncryptedTextField.from_db_value(%s) -> %s', value, dec)
        return dec

    # invoked before saving python value to db value
    def get_prep_value(self, value):
        logging_sensitive('EncryptedTextField.get_prep_value value: %s', value)
        enc = self.crypt.encrypt(value)
        logging_sensitive('EncryptedTextField.get_prep_value(%s) -> %s', value, enc)
        return enc


class User(models.Model):
    sub = models.CharField(max_length=256)
    provider = models.CharField(max_length=256)
    user_name = models.CharField(unique=True, max_length=256)
    name = EncryptedTextField()
    email = EncryptedTextField(default='')

    class Meta:
        unique_together = (('sub', 'provider'),)


class Token(models.Model):
    '''
    OpenID Connect/OAuth 2.0 token information
    '''
    user = models.ForeignKey('User', on_delete=models.CASCADE)
    access_token = EncryptedTextField()  # unknown size
    refresh_token = EncryptedTextField()  # unknown size
    expires = models.DateTimeField()
    provider = models.CharField(max_length=256)
    issuer = models.CharField(max_length=256)
    enabled = models.BooleanField(default=True)
    scopes = models.ManyToManyField('Scope')
    nonce = models.ManyToManyField('Nonce')
    access_token_hash = models.TextField()


class Scope(models.Model):
    name = models.CharField(max_length=256)  # arbitrary but unlikely to be exceeded


class API_key(models.Model):
    '''
    Keys generated for client applications
    '''
    key_hash = models.CharField(max_length=256)  # the sha256 of the api key
    owner = EncryptedTextField()  # short string describing what this api key is used for/by
    enabled = models.BooleanField(default=True)


class User_key(models.Model):
    '''
    Keys generated for users
    '''
    id = models.CharField(primary_key=True, max_length=256)
    key_hash = models.CharField(max_length=256)
    label = models.CharField(max_length=256, null=True, blank=True)
    creation_time = models.DateTimeField(auto_now_add=True)
    user = models.ForeignKey('User', on_delete=models.CASCADE)


class Nonce(models.Model):
    '''
    Nonces used for req/resp exchanges and auth flows
    '''
    value = models.TextField()  # TODO encrypt this
    creation_time = models.DateTimeField(auto_now_add=True)


class PendingCallback(models.Model):
    '''
    Used for sharing state between processes because python can't run real threads
    '''
    uid = models.CharField(max_length=256)  # same type as User.sub
    state = EncryptedTextField()
    nonce = EncryptedTextField()
    scopes = models.ManyToManyField('Scope')
    provider = models.CharField(max_length=256)  # config.json must limit
    url = EncryptedTextField()
    return_to = EncryptedTextField()
    creation_time = models.DateTimeField(auto_now_add=True)


# TODO remove, obsolete
# class BlockingRequest(models.Model):
#     uid = models.CharField(max_length=256) # same type as User.sub
#     nonce = EncryptedTextField()
#     scopes = models.ManyToManyField('Scope')
#     provider = models.CharField(max_length=256)
#     socket_file = models.CharField(max_length=256) # path to socket file
#     creation_time = models.DateTimeField(auto_now_add=True)


class OIDCMetadataCache(models.Model):
    '''
    Used for caching OpenID Connect provider metadata.
    It does not change often and is refreshed after an expiration period
    '''
    value = models.TextField()  # arbitrary length. careful about what is under metadata_url in config.json, could DoS
    retrieval_time = models.DateTimeField(auto_now_add=True)
    provider = models.CharField(max_length=256)
