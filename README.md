[![Build Status](https://travis-ci.com/heliumdatacommons/auth_microservice.svg?branch=master)](https://travis-ci.com/heliumdatacommons/auth_microservice)

# auth_microservice

Microservice which abstracts out OAuth2/OpenID exchanges and token management from applications

## Installation

Create a service account and set up directories owned/used by it
```
$ sudo groupadd auth_microservice
$ sudo useradd -m -g auth_microservice auth_microservice
$ sudo mkdir /etc/auth_microservice
$ sudo chown -R auth_microservice:auth_microservice /etc/auth_microservice
```

Switch to this account, all app-specific operations will be executed as the service account,
which does not have admin privileges
```
$ sudo su - auth_microservice
[auth_microservice] $ 
```

Install python 2.7 or greater. This example uses 3.6.

```
[auth_microservice] $ git clone https://github.com/heliumdatacommons/auth_microservice.git
[auth_microservice] $ cd auth_microservice/
[auth_microservice] $ cp example/config/* /etc/auth_microservice
[auth_microservice] $ rename .example '' /etc/auth_microservice/*.example
```

Edit the files in `/etc/auth_microservice`, filling them in with appropriate values.
These are loaded by the microservice on startup and are used as the initial admin api key,
the database user/pass, and the database encryption key.
The app expects (requires) the keys to be stored as 64 bytes of hexadecimal (representing 32 binary bytes). The admin key, the db key, and the db password should all be completely different. A cross-platform way to generate a 64 byte hex string is:

`$ python3 -c "import os, binascii; print(binascii.hexlify(os.urandom(32)).decode('utf-8'))"`

or without python

`$ dd if=/dev/urandom bs=1 count=32 status=none | xxd -p -c1000`

If not created beforehand, the app will also create a file named `.django.key`
in the django project root directory which is used as Django's secret key.
This is used for sessions and Django hash, signing, and token seeding.
For most cases it is fine to just let the app generate its own django key.
The value of this should not be shared. If it is, just delete it and restart the app,
and let it generate a new one.

Now install the app

TODO: recheck the dependencies; they are modified after cleanup
```
[auth_microservice] $ python3.6 -m venv venv && source venv/bin/activate
[auth_microservice] $ pip install .
[auth_microservice] $ ./manage.py runserver 0.0.0.0:8080
```

There is database setup that must be performed as a user with sudo access.
First remember the password you set in `db.credentials` earlier, then run the following commands:
```
[auth_microservice] $ exit
$ sudo bash /home/auth_microservice/auth_microservice/example/setup.sh <your-db-password>
$ sudo su - auth_microservice
[auth_microservice] $
```

# Running

`uWSGI` is the recommended way to run the server.
`uwsgi.ini` is provided with a basic default configuration,
which can be changed to meet other environment conditions.

```
$ uwsgi --ini ./uwsgi.ini
```

To expose this on an external interface, we can use any http server to wrap localhost 8000 (default port).
For `nginx`, add the following to /etc/nginx/nginx.conf in the http block.
If a conflicting path is already in use on 443, the django app can be placed on a sub-path in nginx, like `/auth`:
```
 server {
        listen       443 ssl;
        listen       [::]:443 ssl;
        server_name  test.commonsshare.org;
        ssl_certificate /opt/certs/auth_microservice.crt;
        ssl_certificate_key /opt/certs/auth_microservice.key;
        root         /usr/share/nginx/html;
        # Load configuration files for the default server block.
        include /etc/nginx/default.d/*.conf;
        location / {
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_pass http://localhost:8000;
        }
    }
```

# Configuration

## config.json

### Providers

* `additional_params`: string (default empty) with (extra) parameters for the authorization url.
In case of OpenID Connect, most params (like `scope`, `response_type`, and `access_type`) are
already generated. For OAuth2, there are no default parameters.

* `additional_scopes`: list of additional scopes that will be requested via the authorization URL.

* `user_name_from_token`: list of token attributes to use as `user_name` (tried in order,
first existing attribute wins) (default to `preferred_username` and `email`)

* `name_from_token`: list of token attributes to use as `name` (tried in order,
first existing attribute wins) (default to `name`)

#### OpenID Connect

* prompt: boolean (default True): adds `prompt` parameter for `login` and `consent` to the authorization url

# Development

## Unittests

### tox

Unittests use `tox` to run the tests (under `token_service/tests/cases`) with different combinations of
`python` and `Django`.

E.g. to run the tests with `python 2.7` and `Django 1.8`, you use
```
python2 -m tox -e py27-django18
```

### pytest

The testing itself uses `pytest`, and you can easily rerun the tests
(without `flake8` or coverage tests) using
```
.tox/py27-django18/bin/pytest
```
Some interesting option for `pytest` are
* `-vvv`: very verbose, show eg the migrations
* `--traceconfig` to show the pytest plugins (incl the `conftest.py` customisation)

### Issues

* If tests fail with `... django.db.utils.OperationalError: no such column: ...`, you need to update the migrations (see below)


## Migrations

With `tox`, it is very easy to make new migrations.

One can generate the migrations using any version of `python` and `Django`,
but it looks like `py36-django20` produces backwards compatible code
(whereas e.g. `py27-django18` does not produce `py3` compatible code).


```
HERE=$PWD
SP=.tox/py36-django20/lib/python3.6/site-packages
MANAGE=django/conf/project_template/

export DJANGO_SETTINGS_MODULE=token_service.tests.settings

cd $SP/$MANAGE
cp manage.py.tpl manage.py
PYTHONPATH=$HERE/$SP python3 $HERE/$SP/$MANAGE/manage.py makemigrations token_service
```

This will create the new migration file in `$HERE/$SP/token_service/migrations`
and you can copy it back the repo.


It might prompt for questions etc, see example output below


```
Did you rename api_key.key to api_key.key_hash (a CharField)? [y/N] y
Did you rename token.user_id to token.user (a ForeignKey)? [y/N] y
You are trying to add a non-nullable field 'owner' to api_key without a default; we can't do that (the database needs something to populate existing rows).
Please select a fix:
 1) Provide a one-off default now (will be set on all existing rows)
 2) Quit, and let me add a default in models.py
Select an option: 1
Please enter the default value now, as valid Python
The datetime and django.utils.timezone modules are available, so you can do e.g. timezone.now()
>>> ''      
You are trying to add a non-nullable field 'access_token_hash' to token without a default; we can't do that (the database needs something to populate existing rows).
Please select a fix:
 1) Provide a one-off default now (will be set on all existing rows)
 2) Quit, and let me add a default in models.py
Select an option: 1
Please enter the default value now, as valid Python
The datetime and django.utils.timezone modules are available, so you can do e.g. timezone.now()
>>> ''
You are trying to add a non-nullable field 'id' to token without a default; we can't do that (the database needs something to populate existing rows).
Please select a fix:
 1) Provide a one-off default now (will be set on all existing rows)
 2) Quit, and let me add a default in models.py
Select an option: 0
Please select a valid option: 1
Please enter the default value now, as valid Python
The datetime and django.utils.timezone modules are available, so you can do e.g. timezone.now()
>>> 1
You are trying to add a non-nullable field 'name' to user without a default; we can't do that (the database needs something to populate existing rows).
Please select a fix:
 1) Provide a one-off default now (will be set on all existing rows)
 2) Quit, and let me add a default in models.py
Select an option: 1
Please enter the default value now, as valid Python
The datetime and django.utils.timezone modules are available, so you can do e.g. timezone.now()
>>> ''
Migrations for 'token_service':
  0002_auto_20180907_0526.py:
    - Create model Nonce
    - Create model OIDCMetadataCache
    - Create model PendingCallback
    - Create model User_key
    - Rename field key on api_key to key_hash
    - Rename field user_id on token to user
    - Remove field token_id from token
    - Remove field user_id from user
    - Add field enabled to api_key
    - Add field owner to api_key
    - Add field access_token_hash to token
    - Add field id to token
    - Add field name to user
    - Alter field id on user
    - Alter field user_name on user
    - Add field user to user_key
    - Add field nonce to token

```
