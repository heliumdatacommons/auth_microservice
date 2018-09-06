# auth_microservice
Microservice which abstracts out OAuth2/OpenID exchanges and token management from applications

Installation:

Create a service account and set up directories owned/used by it
```
$ sudo groupadd auth_microservice
$ sudo useradd -m -g auth_microservice auth_microservice
$ sudo mkdir /etc/auth_microservice
$ sudo chown -R auth_microservice:auth_microservice /etc/auth_microservice
```

Switch to this account, all app-specific operations will be executed as the service account, which does not have admin privileges
```
$ sudo su - auth_microservice
[auth_microservice] $ 
```

Install python 3.5 or greater. This example uses 3.6.

```
[auth_microservice] $ git clone https://github.com/heliumdatacommons/auth_microservice.git
[auth_microservice] $ cd auth_microservice/
[auth_microservice] $ cp config/* /etc/auth_microservice
```

Edit the files in /etc/auth_microservice, filling them in with appropriate values. These are loaded by the microservice on startup and are used as the initial admin api key, the database user/pass, and the database encryption key. Once filled in, remove the '.example' extension from each. The app expects (requires) the keys to be stored as 64 bytes of hexadecimal (representing 32 binary bytes). The admin key, the db key, and the db password should all be completely different. A cross-platform way to generate a 64 byte hex string is:

`$ python3 -c "import os, binascii; print(binascii.hexlify(os.urandom(32)).decode('utf-8'))"`

or without python

`$ dd if=/dev/urandom bs=1 count=32 status=none | xxd -p -c1000`

If not created beforehand, the app will also create a file named '.django.key' in the django project root directory which is used as Django's secret key. This is used for sessions and Django hash, signing, and token seeding. For most cases it is fine to just let the app generate its own django key. The value of this should not be shared. If it is, just delete it and restart the app, and let it generate a new one. 

Now install the app

```
[auth_microservice] $ cd src/microservice
[auth_microservice] $ python3.6 -m venv venv && source venv/bin/activate
[auth_microservice] $ pip install .
[auth_microservice] $ ./manage.py runserver 0.0.0.0:8080
```

There is database setup that must be performed as a user with sudo access.  First remember the password you set in db.credentials earlier, then run the following commands:
```
[auth_microservice] $ exit
$ sudo bash /home/auth_microservice/auth_microservice/src/microservice/setup.sh <your-db-password>
$ sudo su - auth_microservice
[auth_microservice] $
```

uWSGI is the recommended way to run the server. `uwsgi.ini` is provided with a basic default configuration, which can be changed to meet other environment conditions.

```
$ uwsgi --ini ./uwsgi.ini
```

To expose this on an external interface, we can use any http server to wrap localhost 8000 (default port).  For nginx, add the following to /etc/nginx/nginx.conf in the http block.  If a conflicting path is already in use on 443, the django app can be placed on a sub-path in nginx, like /auth:
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

