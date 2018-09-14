import binascii
import json
from token_service import crypt
# pointless to do a whole from ... import * here
from token_service.base_settings import make_database_mem

DEBUG = True

SECRET_KEY = 'this-should-be-top-secret'

DATABASES = {
    'default': make_database_mem()
}

SITE_ID = 1

MIDDLEWARE_CLASSES = [
    'django.middleware.common.CommonMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

INSTALLED_APPS = [
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.sites',
    'django.contrib.messages',
    'django.contrib.admin',
    'token_service',
    'django.contrib.staticfiles',
]

ROOT_URLCONF = 'token_service.tests.app.urls'

USE_TZ = True

LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'handlers': {
        'console': {
            'class': 'logging.StreamHandler',
        },
    },
    'loggers': {
        'toke_service': {
            'handlers': ['console'],
            'level': 'DEBUG',
        },
    },
}

# token_service
DB_KEY = binascii.unhexlify('1' * 64)
crypt.instance = crypt.Crypt(DB_KEY)

ADMIN_KEY = '2' * 64
import token_service.config
token_service.config.admin_key = ADMIN_KEY

JSONCONFIG = """{
    "redirect_uri": "https://example.org/authcallback",
    "callback_queue_len": 50,
    "providers": {
        "prov1": {
            "standard": "OpenID Connect",
            "client_id": "123abc",
            "client_secret": "secret123",
            "metadata_url": "https://example.provider/.well-known/openid-configuration"
        },
        "prov2": {
            "standard": "OAuth 2.0",
            "client_id": "456def",
            "client_secret": "secret456",
            "authorization_endpoint": "https://example2.provider/authorization-path",
            "token_endpoint": "https://example2.provider/token-path"
        }
    }
}
"""
token_service.config.Config = json.loads(JSONCONFIG)
