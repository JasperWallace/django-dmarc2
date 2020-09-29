# ----------------------------------------------------------------------
# Copyright (c) 2015-2019, Persistent Objects Ltd http://p-o.co.uk/
#
# License: BSD
# ----------------------------------------------------------------------
"""
DMARC urls
https://dmarc.org/resources/specification/
"""
from django.conf.urls import url

from dmarc import views

app_name = 'dmarc'
urlpatterns = [
    url("^report/$", views.dmarc_report, name='dmarc_report'),
    url("^report/csv/$", views.dmarc_csv, name='dmarc_csv'),
    url("^report/json/$", views.dmarc_json, name='dmarc_json'),
    url(r"^report/view/(?P<id>\d+)/$", views.dmarc_view_report, name='dmarc_report'),
    url("^report/counts_by_date/$", views.dmarc_count_bydate, name='dmarc_count_bydate'),
]
