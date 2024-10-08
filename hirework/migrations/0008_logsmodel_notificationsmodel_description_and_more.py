# Generated by Django 5.0.4 on 2024-07-19 08:55

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('hirework', '0007_notificationsmodel'),
    ]

    operations = [
        migrations.CreateModel(
            name='LogsModel',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('api', models.CharField(max_length=150)),
                ('method', models.CharField(max_length=100)),
                ('error', models.TextField()),
                ('created_at', models.DateTimeField(auto_now_add=True)),
            ],
        ),
        migrations.AddField(
            model_name='notificationsmodel',
            name='description',
            field=models.TextField(default=''),
        ),
        migrations.AlterField(
            model_name='jobsmodel',
            name='end_salary',
            field=models.FloatField(default=1),
            preserve_default=False,
        ),
        migrations.AlterField(
            model_name='jobsmodel',
            name='start_salary',
            field=models.FloatField(blank=True, null=True),
        ),
    ]
