"""
Delete all pending callback, token and user instances

python -m auth_microservice.manage runscript wipe
"""

from token_service import models


def run():
    for model in [
            models.PendingCallback,
            models.Token,
            models.User,
    ]:
        for entry in model.objects.all():
            entry.delete()
