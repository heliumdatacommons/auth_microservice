"""
To be run using python manage.py runscripts list_tokens

cd .../lib/python2.7/site-packages/django/conf/project_template
export DJANGO_SETTINGS_MODULE=token_service.settings
python manage.py runscripts list_tokens
"""

import sys
from token_service import models

def run():
    uid = ''

    print('listing tokens for uid: [{}]'.format(uid))
    for t in models.Token.objects.filter(user__id=uid):
        print(t.access_token)
        for s in t.scopes.all():
            print(s.name)
        print()
