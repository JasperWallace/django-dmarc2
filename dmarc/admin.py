# ----------------------------------------------------------------------
# Copyright (c) 2015-2019, Persistent Objects Ltd http://p-o.co.uk/
#
# License: BSD
# ----------------------------------------------------------------------
"""
DMARC models for managing Aggregate Reports
https://dmarc.org/resources/specification/
"""
from django.contrib import admin

from dmarc.models import FBReport, Report


class ReportAdmin(admin.ModelAdmin):
    """Report display options"""

    actions = []
    list_display = ['report_id', 'reporter', 'date_begin']
    list_filter = ['date_begin', 'reporter']
    readonly_fields = [
        'report_id', 'reporter',
        'date_begin', 'date_end', 'policy_domain',
        'policy_adkim', 'policy_aspf',
        'policy_p', 'policy_sp',
        'policy_pct',
        'nice_xml'
    ]
    exclude = ['report_xml', ]
    order = ['-id']

    def has_add_permission(self, request):
        return False


class FBReportAdmin(admin.ModelAdmin):
    """Feedback Report display options"""

    actions = []
    list_display = ['reporter', 'date', 'source_ip', 'domain', 'email_from']
    list_filter = ['date', 'reporter', 'source_ip']
    exclude = ['email_source', 'feedback_report', 'feedback_source', 'description']
    readonly_fields = [
        'reporter', 'date', 'source_ip',
        'domain', 'email_from', 'email_subject',
        'spf_alignment', 'dkim_alignment',
        'dmarc_result', 'nice_description', 'nice_email_source',
        'nice_feedback_report', 'nice_feedback_source'
    ]
    order = ['-id']

    def has_add_permission(self, request):
        return False


admin.site.register(Report, ReportAdmin)
admin.site.register(FBReport, FBReportAdmin)
