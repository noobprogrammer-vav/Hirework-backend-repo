# Generated by Django 5.0.4 on 2024-06-29 05:07

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('hirework', '0003_usermodel_password'),
    ]

    operations = [
        migrations.AlterField(
            model_name='usertokenmodel',
            name='updated_at',
            field=models.DateTimeField(auto_now=True),
        ),
    ]
