# ----------------------------------------------------------------------
# Copyright (c) 2015-2019, Persistent Objects Ltd http://p-o.co.uk/
#
# License: BSD
# ----------------------------------------------------------------------
"""Django application configuration"""
from __future__ import unicode_literals

from django.apps import AppConfig


class DmarcConfig(AppConfig):
    """DMARC application configuration"""

    name = 'dmarc'
    verbose_name = "DMARC feedback report manager"
