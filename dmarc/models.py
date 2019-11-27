# ----------------------------------------------------------------------
# Copyright (c) 2015-2019, Persistent Objects Ltd http://p-o.co.uk/
#
# License: BSD
# ----------------------------------------------------------------------
"""
DMARC models for managing Aggregate Reports
https://dmarc.org/resources/specification/
"""
from django.db import models


class Reporter(models.Model):
    """DMARC reporter"""

    org_name = models.CharField('Organisation', unique=True, max_length=100)
    email = models.EmailField()

    def __unicode__(self):
        return self.org_name


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

    def __unicode__(self):
        return self.report_id

    class Meta(object):
        """Model constraints"""
        # pylint: disable=too-few-public-methods

        unique_together = (("reporter", "report_id", "date_begin"),)


class Record(models.Model):
    """DMARC report record"""

    report = models.ForeignKey(Report, related_name='records', on_delete=models.CASCADE)
    source_ip = models.CharField(max_length=39)
    recordcount = models.IntegerField()
    policyevaluated_disposition = models.CharField(max_length=10)
    policyevaluated_dkim = models.CharField(max_length=4)
    policyevaluated_spf = models.CharField(max_length=4)
    policyevaluated_reasontype = models.CharField(blank=True, max_length=75)
    policyevaluated_reasoncomment = models.CharField(blank=True, max_length=100)
    identifier_headerfrom = models.CharField(max_length=100)

    def __unicode__(self):
        return self.source_ip


class Result(models.Model):
    """DMARC report record result"""

    record = models.ForeignKey(Record, related_name='results', on_delete=models.CASCADE)
    record_type = models.CharField(max_length=4)
    domain = models.CharField(max_length=100)
    result = models.CharField(max_length=9)

    def __unicode__(self):
        return "%s:%s-%s" % (str(self.pk), self.record_type, self.domain,)


class FBReporter(models.Model):
    """DMARC feedback reporter"""

    org_name = models.CharField('Organisation', unique=True, max_length=100)
    email = models.EmailField()

    def __unicode__(self):
        return self.email

    def save(self, *args, **kwargs):
        # pylint: disable=arguments-differ
        if not self.org_name:
            self.org_name = self.email
        super(FBReporter, self).save(*args, **kwargs)


class FBReport(models.Model):
    """DMARC feedback report"""

    reporter = models.ForeignKey(FBReporter, on_delete=models.CASCADE)
    date = models.DateTimeField(db_index=True)
    source_ip = models.CharField(max_length=39)
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

    def __unicode__(self):
        msg = '{} {} {} {} {}'.format(
            self.date,
            self.domain,
            self.source_ip,
            self.email_from,
            self.email_subject
        )
        return msg
