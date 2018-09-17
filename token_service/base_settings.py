"""
Generic settings and functions to create a proper django settings file for
token_service.

Can be used in settings.py as

    from token_service.base_settings import *

"""
import binascii
import json
import logging
import os
import random
import traceback
from token_service import crypt
import token_service.config as tsc
from token_service.util import logging_sensitive


# set token_service.config.debug_sensitive if you want (debug) logging of sensitive data

# Build paths inside the project like this: os.path.join(BASE_DIR, ...)
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

SECRET_KEY_LEN = 50
DB_KEY_LEN = 32
ADMIN_KEY_LEN = 32

TOKEN_SERVICE_DJANGO_KEY = os.path.join(BASE_DIR, '.django.key')

TOKEN_SERVICE_BASEDIR = '/etc/auth_microservice'
TOKEN_SERVICE_DB_CFG = os.path.join(TOKEN_SERVICE_BASEDIR, 'db.credentials')
TOKEN_SERVICE_DB_KEY = os.path.join(TOKEN_SERVICE_BASEDIR, 'db.key')
TOKEN_SERVICE_ADMIN_KEY = os.path.join(TOKEN_SERVICE_BASEDIR, 'admin.key')
TOKEN_SERVICE_CONFIG = os.path.join(TOKEN_SERVICE_BASEDIR, 'config.json')
TOKEN_SERVICE_DJANGO_KEY_ALT = os.path.join(TOKEN_SERVICE_BASEDIR, 'django.key')


def make_secret_key(keylen=SECRET_KEY_LEN):
    if 'SECRET_KEY' in locals():
        logging.info('django secret key present')
        secret_key = locals()['SECRET_KEY']
    else:
        loaded_django_key = False
        for keyfn in [TOKEN_SERVICE_DJANGO_KEY, TOKEN_SERVICE_DJANGO_KEY_ALT]:
            if os.path.isfile(keyfn):
                logging.info('Trying to load django secret key from %s', keyfn)
                with open(keyfn, 'r') as f:
                    secret_key = f.readline().strip()
                    if len(secret_key) == keylen:
                        loaded_django_key = True
                        break
                    else:
                        logging.warn('saved django key %s has incorrect size', keyfn)
            else:
                logging.info('No django secret key %s', keyfn)
        if not loaded_django_key:
            logging.info('No django secret key loaded, trying to create one at %s', TOKEN_SERVICE_DJANGO_KEY)
            ascii_printable = [chr(c) for c in range(ord('!'), ord('~')+1)]
            secret_key = ''.join([random.SystemRandom().choice(ascii_printable) for i in range(0, keylen)])
            try:
                with open(TOKEN_SERVICE_DJANGO_KEY, 'w') as f:
                    f.write(secret_key)
            except OSError:
                logging.error('Could not save django key %s. Will use a different key being for each execution',
                              TOKEN_SERVICE_DJANGO_KEY)
                traceback.print_exc()
    return secret_key


def make_database():
    logging.info('creating database')
    with open(TOKEN_SERVICE_DB_CFG, 'r') as f:
        d = json.loads(f.read())
        host = d['host']
        port = d['port']
        user = d['user']
        password = d['password']
        backend = d.get('backend', 'django.db.backends.postgresql')
        name = d.get('name', 'auth_microservice')

        return {
            'ENGINE': backend,
            'NAME': name,
            'USER': user,
            'PASSWORD': password,
            'HOST': host,
            'PORT': port,
        }


def make_database_mem():
    """In memory sqlite config; do NOT use in production"""
    logging.info('creating memory database')
    return {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': ':memory:',
    }


def get_db_key(keylen=DB_KEY_LEN):
    """
    reads db key from file, create crypt instance
    """
    logging.info('reading DB key from %s', TOKEN_SERVICE_DB_KEY)
    with open(TOKEN_SERVICE_DB_KEY, 'r') as f:
        d = f.readline().strip()
        raw_len = keylen * 2
        if len(d) != raw_len:
            logging.warn('db key file %s must contain a %s byte hexidecimal string',
                         TOKEN_SERVICE_DB_KEY, raw_len)
        db_key = binascii.unhexlify(d.encode('utf-8'))
        crypt.instance = crypt.Crypt(db_key)
        logging_sensitive("read db_key and created crypt instance: %s", db_key)
        return db_key


def get_admin_key(keylen=ADMIN_KEY_LEN):
    """
    reads admin key from file (and sets admin in config module)
    """
    logging.info('reading admin key from %s', TOKEN_SERVICE_ADMIN_KEY)
    with open(TOKEN_SERVICE_ADMIN_KEY, 'r') as f:
        d = f.readline().strip()
        raw_len = keylen * 2
        if len(d) != raw_len:
            logging.warn('admin key file %s must contain a %s byte hexidecimal string',
                         TOKEN_SERVICE_ADMIN_KEY, raw_len)
        admin_key = d.encode('utf-8')  # this remains as hex
        tsc.admin_key = admin_key
        logging_sensitive("read admin_key: %s", admin_key)
        return admin_key


def load_json_config():
    # Load application configuration
    logging.info('loading JSON configuration from %s', TOKEN_SERVICE_CONFIG)
    with open(TOKEN_SERVICE_CONFIG, 'r') as f:
        d = json.loads(f.read())
        if 'providers' not in d:
            raise RuntimeError('providers missing from config')

        for tag in d['providers']:
            p = d['providers'][tag]
            if 'standard' not in p:
                raise RuntimeError('provider config did not specify a standard')
            if p['standard'] == 'OAuth 2.0':
                # TODO: replace assert with actual check
                assert('authorization_endpoint' in p)
                assert('token_endpoint' in p)
            elif p['standard'] == 'OpenID Connect':
                assert('metadata_url' in p)

            # set defaults if not configured
            if 'url_expiration_timeout' not in d:
                d['url_expiration_timeout'] = 60
            if int(d['url_expiration_timeout']) <= 0:
                raise RuntimeError('url_expiration_timeout must be a positive integer')
            else:
                d['url_expiration_timeout'] = int(d['url_expiration_timeout'])

            if 'real_time_validate_cache_retention_timeout' not in d:
                d['real_time_validate_cache_retention_timeout'] = 30
            if int(d['real_time_validate_cache_retention_timeout']) < 0:
                raise RuntimeError('real_time_validate_cache_retention_timeout must be a positive integer')
            else:
                d['real_time_validate_cache_retention_timeout'] = int(d['real_time_validate_cache_retention_timeout'])

        tsc.Config = d
