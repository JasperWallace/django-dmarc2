# ----------------------------------------------------------------------
# Copyright (c) 2015-2019, Persistent Objects Ltd http://p-o.co.uk/
#
# License: BSD
# ----------------------------------------------------------------------
"""
DMARC models for managing Aggregate Reports
https://dmarc.org/resources/specification/
"""
import xml.dom.minidom

from django.contrib.postgres.indexes import GistIndex
from django.db import models
from django.utils.safestring import mark_safe
from netfields import InetAddressField, NetManager
from pygments import highlight
from pygments.formatters import HtmlFormatter
from pygments.lexers.email import EmailLexer
from pygments.lexers.html import XmlLexer


class Reporter(models.Model):
    """DMARC reporter"""

    org_name = models.CharField('Organisation', unique=True, max_length=100)
    email = models.EmailField()

    def __str__(self):
        return str(self.org_name)


class Report(models.Model):
    """DMARC report metadata"""

    report_id = models.CharField(max_length=100)
    reporter = models.ForeignKey(Reporter, on_delete=models.CASCADE)
    date_begin = models.DateTimeField(db_index=True)
    date_end = models.DateTimeField()
    policy_domain = models.CharField(max_length=100)
    policy_adkim = models.CharField('DKIM alignment mode', max_length=1)
    policy_aspf = models.CharField('SPF alignment mode', max_length=1)
    policy_p = models.CharField('Requested handling policy', max_length=10)
    policy_sp = models.CharField('Requested handling policy for subdomains', max_length=10)
    policy_pct = models.SmallIntegerField('Sampling rate')
    report_xml = models.TextField(blank=True)

    def __str__(self):
        return str(self.report_id)

    def nice_xml(self):
        """returns html formatted report xml"""

        xml_out = self.report_xml
        # if it's not got many newlines
        # it's probably just on one, so prettyfy it.
        if self.report_xml.count("\n") < 2:
            dom = xml.dom.minidom.parseString(xml_out)
            xml_out = dom.toprettyxml(indent="  ")

        xml_html = highlight(xml_out, XmlLexer(), HtmlFormatter(noclasses=True))
        return mark_safe(xml_html)

    class Meta:
        """Model constraints"""
        # pylint: disable=too-few-public-methods

        unique_together = (("reporter", "report_id", "date_begin"),)


class Record(models.Model):
    """DMARC report record"""

    report = models.ForeignKey(Report, related_name='records', on_delete=models.CASCADE)
    source_ip = InetAddressField(store_prefix_length=False)
    recordcount = models.IntegerField()
    policyevaluated_disposition = models.CharField(max_length=10)
    policyevaluated_dkim = models.CharField(max_length=4)
    policyevaluated_spf = models.CharField(max_length=4)
    policyevaluated_reasontype = models.CharField(blank=True, max_length=75)
    policyevaluated_reasoncomment = models.CharField(blank=True, max_length=100)
    identifier_headerfrom = models.CharField(max_length=100)
    objects = NetManager()

    def __str__(self):
        return str(self.source_ip)

    class Meta:
        indexes = (
            GistIndex(
                fields=('source_ip',), opclasses=('inet_ops',),
                name='dmarc_record_source_ip_idx'
            ),
        )


class Result(models.Model):
    """DMARC report record result"""

    record = models.ForeignKey(Record, related_name='results', on_delete=models.CASCADE)
    record_type = models.CharField(max_length=4)
    domain = models.CharField(max_length=100)
    result = models.CharField(max_length=9)

    def __str__(self):
        return "%s:%s-%s" % (str(self.pk), self.record_type, self.domain,)


class FBReporter(models.Model):
    """DMARC feedback reporter"""

    org_name = models.CharField('Organisation', unique=True, max_length=100)
    email = models.EmailField()

    def __str__(self):
        return str(self.email)

    def save(self, *args, **kwargs):
        # pylint: disable=arguments-differ
        if not self.org_name:
            self.org_name = self.email
        super(FBReporter, self).save(*args, **kwargs)


class FBReport(models.Model):
    """DMARC feedback report"""

    reporter = models.ForeignKey(FBReporter, on_delete=models.CASCADE)
    date = models.DateTimeField(db_index=True)
    source_ip = InetAddressField(store_prefix_length=False)
    domain = models.CharField(max_length=100)
    email_from = models.CharField(max_length=100, blank=True)
    email_subject = models.CharField(max_length=100, blank=True)
    spf_alignment = models.CharField(max_length=10, blank=True)
    dkim_alignment = models.CharField(max_length=10, blank=True)
    dmarc_result = models.CharField(max_length=10, blank=True)
    description = models.TextField('human readable feedback', blank=True)
    email_source = models.TextField('source email including rfc822 headers', blank=True)
    feedback_report = models.TextField(blank=True)
    feedback_source = models.TextField()

    objects = NetManager()

    def nice_description(self):
        """returns html formatted description"""

        email_html = highlight(self.description, EmailLexer(), HtmlFormatter(noclasses=True))
        return mark_safe(email_html)

    def nice_email_source(self):
        """returns html formatted source_email"""

        email_html = highlight(self.email_source, EmailLexer(), HtmlFormatter(noclasses=True))
        return mark_safe(email_html)

    def nice_feedback_report(self):
        """returns html formatted source_email"""

        email_html = highlight(self.feedback_report, EmailLexer(), HtmlFormatter(noclasses=True))
        return mark_safe(email_html)

    def nice_feedback_source(self):
        """returns html formatted feedback source"""

        # MIMELexer might be better here
        # but the results wern't as nice.
        email_html = highlight(self.feedback_source, EmailLexer(), HtmlFormatter(noclasses=True))
        return mark_safe(email_html)

    def __str__(self):
        msg = '{} {} {} {} {}'.format(
            self.date,
            self.domain,
            self.source_ip,
            self.email_from,
            self.email_subject
        )
        return msg

    class Meta:
        indexes = (
            GistIndex(
                fields=('source_ip',), opclasses=('inet_ops',),
                name='dmarc_fbreport_source_ip_idx'
            ),
        )
