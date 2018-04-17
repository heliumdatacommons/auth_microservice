from token_service import models

for p in models.PendingCallback.objects.all():
    p.delete()

for b in models.BlockingRequest.objects.all():
    b.delete()

for t in models.Token.objects.all():
    t.delete()

for u in models.User.objects.all():
    u.delete()
