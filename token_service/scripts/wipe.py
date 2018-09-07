"""
To be run using python manage.py runscripts wipe

cd .../lib/python2.7/site-packages/django/conf/project_template
export DJANGO_SETTINGS_MODULE=token_service.settings
python manage.py runscripts wipe
"""

from token_service import models

def run():
    for model in [
            models.PendingCallback,
            models.BlockingRequest,
            models.Token,
            models.User,
    ]:
        for entry in model.objects.all():
            entry.delete()
