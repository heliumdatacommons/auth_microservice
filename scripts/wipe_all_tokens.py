from token_service import models

for t in models.Token.objects.all():
    t.delete()

