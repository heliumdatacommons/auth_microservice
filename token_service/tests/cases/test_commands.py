from django.core.management import call_command
from django.test import TestCase
from django.utils.six import StringIO


class CommandsTest(TestCase):

    def test_makemigrations_output(self):
        out = StringIO()
        call_command('makemigrations', 'token_service', stdout=out)
        self.assertIn('No changes detected in app', out.getvalue())
