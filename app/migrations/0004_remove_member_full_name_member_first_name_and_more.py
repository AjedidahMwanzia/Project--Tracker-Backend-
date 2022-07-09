# Generated by Django 4.0.6 on 2022-07-09 06:12

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('app', '0003_member'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='member',
            name='full_name',
        ),
        migrations.AddField(
            model_name='member',
            name='first_name',
            field=models.CharField(max_length=255, null=True),
        ),
        migrations.AddField(
            model_name='member',
            name='last_name',
            field=models.CharField(max_length=255, null=True),
        ),
    ]