# auth_microservice
Microservice which abstracts out OAuth2/OpenID exchanges and token management from applications

Installation:

Install python 3.5 or greater. This example uses 3.6.

```
$ git clone https://github.com/heliumdatacommons/auth_microservice.git
$ cd auth_microservice/
$ sudo mkdir /etc/auth_microservice
$ sudo cp config/* /etc/auth_microservice
```

Edit the files in /etc/auth_microservice, filling them in with appropriate values. These are loaded by the microservice on startup and are used as the initial admin api key, the database user/pass, and the database encryption key. Once filled in, remove the '.example' extension from each. The app expects (requires) the keys to be stored as 64 bytes of hexadecimal (representing 32 binary bytes). The admin key, the db key, and the db password should all be completely different. A cross-platform way to generate a 64 byte hex string is:

`$ python3 -c "import os, binascii; print(binascii.hexlify(os.urandom(32)).decode('utf-8'))"`

or without python

`$ dd if=/dev/urandom bs=1 count=32 status=none | xxd -p -c1000`

If not created beforehand, the app will also create a file named '.django.key' in the django project root directory which is used as Django's secret key. This is used for sessions and Django hash, signing, and token seeding. For most cases it is fine to just let the app generate its own django key. The value of this should not be shared. If it is, just delete it and restart the app, and let it generate a new one. 

Now install the app and test that it installed correctly

```
$ cd src/microservice
$ python3.6 -m venv venv && source venv/bin/activate
$ pip install .
$ ./manage.py runserver 0.0.0.0:8080
```
