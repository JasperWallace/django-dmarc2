# Generated by Django 2.2.13 on 2020-06-20 23:27

from django.db import migrations
import netfields.fields


class Migration(migrations.Migration):

    dependencies = [
        ('dmarc', '0001_initial'),
    ]

    operations = [
        migrations.AddField(
            model_name='fbreport',
            name='source_ip_tmp',
            field=netfields.fields.InetAddressField(max_length=39, null=True, default=False),
            preserve_default=False,
        ),
        migrations.AddField(
            model_name='record',
            name='source_ip_tmp',
            field=netfields.fields.InetAddressField(max_length=39, null=True, default=False),
            preserve_default=False,
        ),
    ]
