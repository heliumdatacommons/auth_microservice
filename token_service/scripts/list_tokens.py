"""
To be run using python manage.py runscripts list_tokens for uid

If uid is empty string, list tokens for all users

python -m auth_microservice.manage runscript list_tokens --script-arg <uid>
"""

from token_service import models
from django.utils.timezone import now

def run(uid):
    tos = models.Token.objects
    if uid:
        msg = 'uid: [{}]'.format(uid)
        tokens = tos.filter(user__id=uid)
    else:
        msg = 'all uids'
        tokens = tos.order_by('user__id')
    print('listing tokens for {}'.format(msg))

    indent = " " * 2
    for t in tokens:
        txt = [t.access_token]
        if not uid:
            txt.append('{}uid {}'.format(indent, t.user_id))

        txt.append('{}scopes: {}'.format(indent, ', '.join([s.name for s in t.scopes.all()])))

        when = (t.expires - now()).seconds / 3600
        if when <= 0:
            msg = '{}expired {:.2f} hours ago ({})'
        else:
            msg = '{}expires in {:.2f} hours ({})'
        txt.append(msg.format(indent, when, t.expires))

        print("\n".join(txt + ['']))
