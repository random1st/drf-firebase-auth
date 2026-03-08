# -*- coding: utf-8 -*-
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('drf_firebase_auth', '0001_initial'),
    ]

    operations = [
        migrations.AlterField(
            model_name='firebaseuser',
            name='uid',
            field=models.CharField(max_length=191, unique=True),
        ),
    ]
