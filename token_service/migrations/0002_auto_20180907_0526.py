# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import migrations, models
import token_service.models


class Migration(migrations.Migration):

    dependencies = [
        ('token_service', '0001_initial'),
    ]

    operations = [
        migrations.CreateModel(
            name='Nonce',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('value', models.TextField()),
                ('creation_time', models.DateTimeField(auto_now_add=True)),
            ],
        ),
        migrations.CreateModel(
            name='OIDCMetadataCache',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('value', models.TextField()),
                ('retrieval_time', models.DateTimeField(auto_now_add=True)),
                ('provider', models.CharField(max_length=256)),
            ],
        ),
        migrations.CreateModel(
            name='PendingCallback',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('uid', models.CharField(max_length=256)),
                ('state', token_service.models.EncryptedTextField()),
                ('nonce', token_service.models.EncryptedTextField()),
                ('provider', models.CharField(max_length=256)),
                ('url', token_service.models.EncryptedTextField()),
                ('return_to', token_service.models.EncryptedTextField()),
                ('creation_time', models.DateTimeField(auto_now_add=True)),
                ('scopes', models.ManyToManyField(to='token_service.Scope')),
            ],
        ),
        migrations.CreateModel(
            name='User_key',
            fields=[
                ('id', models.CharField(max_length=256, serialize=False, primary_key=True)),
                ('key_hash', models.CharField(max_length=256)),
                ('label', models.CharField(max_length=256, null=True, blank=True)),
                ('creation_time', models.DateTimeField(auto_now_add=True)),
            ],
        ),
        migrations.RenameField(
            model_name='api_key',
            old_name=b'key',
            new_name='key_hash',
        ),
        migrations.RenameField(
            model_name='token',
            old_name=b'user_id',
            new_name='user',
        ),
        migrations.RemoveField(
            model_name='token',
            name=b'token_id',
        ),
        migrations.RemoveField(
            model_name='user',
            name=b'user_id',
        ),
        migrations.AddField(
            model_name='api_key',
            name='enabled',
            field=models.BooleanField(default=True),
        ),
        migrations.AddField(
            model_name='api_key',
            name='owner',
            field=token_service.models.EncryptedTextField(default=''),
            preserve_default=False,
        ),
        migrations.AddField(
            model_name='token',
            name='access_token_hash',
            field=models.TextField(default=''),
            preserve_default=False,
        ),
        migrations.AddField(
            model_name='token',
            name='id',
            field=models.AutoField(auto_created=True, primary_key=True, default=1, serialize=False, verbose_name='ID'),
            preserve_default=False,
        ),
        migrations.AddField(
            model_name='user',
            name='name',
            field=token_service.models.EncryptedTextField(default=''),
            preserve_default=False,
        ),
        migrations.AlterField(
            model_name='user',
            name=b'id',
            field=models.CharField(max_length=256, serialize=False, primary_key=True),
        ),
        migrations.AlterField(
            model_name='user',
            name=b'user_name',
            field=models.CharField(unique=True, max_length=256),
        ),
        migrations.AddField(
            model_name='user_key',
            name='user',
            field=models.ForeignKey(to='token_service.User'),
        ),
        migrations.AddField(
            model_name='token',
            name='nonce',
            field=models.ManyToManyField(to='token_service.Nonce'),
        ),
    ]
