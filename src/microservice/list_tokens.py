import sys
from token_service import models
uid = ''

print('listing tokens for uid: [{}]'.format(uid))
for t in models.Token.objects.filter(user__id=uid):
    print(t.access_token)
    for s in t.scopes.all():
        print(s.name)
    print()
