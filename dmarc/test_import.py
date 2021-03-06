# ----------------------------------------------------------------------
# Copyright (c) 2015-2019, Persistent Objects Ltd http://p-o.co.uk/
#
# License: BSD
# ----------------------------------------------------------------------
"""
DMARC tests for importing Aggregate Reports
https://dmarc.org/resources/specification/
"""
import ipaddress
import os
from datetime import datetime
from io import StringIO

import pytz
from django.conf import settings
from django.contrib.auth.models import User
from django.core.management import call_command
from django.core.management.base import CommandError
from django.test import TestCase
from django.urls import reverse

from dmarc.models import FBReport, FBReporter, Record, Report, Reporter, Result


class ImportDMARCReportTestCase(TestCase):
    """
    Test importing aggregate reports
    """

    def setUp(self):
        """Set up test environment"""
        pass

    def test_import_noargs(self):
        """Test importing without args"""
        msg = 'Check usage, please supply a single DMARC report file or email'
        out = StringIO()
        try:
            call_command('importdmarcreport', stdout=out)
        except CommandError as cmderror:
            msgerror = str(cmderror)
        self.assertIn(msg, msgerror)

    def test_import_filenotfound(self):
        """Test importing xml file not found"""
        msg = 'Error: argument -x/--xml: can\'t open \'filenotfound.xml\''
        msg += ': [Errno 2] No such file or directory: \'filenotfound.xml\''
        out = StringIO()
        msgerror = ''
        try:
            call_command(
                'importdmarcreport',
                '--xml',
                'filenotfound.xml',
                stderr=out)
        except CommandError as cmderror:
            msgerror = str(cmderror)
        self.assertEqual(msgerror, msg)

    def test_importdmarcreport_file(self):
        """Test importing xml file"""
        out = StringIO()
        data = Reporter.objects.all()
        self.assertEqual(len(data), 0)
        dmarcreport = os.path.dirname(os.path.realpath(__file__))
        dmarcreport = os.path.join(dmarcreport, 'tests/dmarcreport.xml')
        call_command('importdmarcreport', '--xml', dmarcreport, stdout=out)
        self.assertIn('', out.getvalue())
        # Reporter object
        data = Reporter.objects.all()
        self.assertEqual(len(data), 1)
        self.assertEqual(data[0].org_name, 'Persistent Objects')
        self.assertEqual(data[0].email, 'ahicks@p-o.co.uk')
        # Report object
        data = Report.objects.all()
        self.assertEqual(len(data), 1)
        self.assertEqual(data[0].report_id, '5edbe461-ccda-1e41-abdb-00c0af3f9715@p-o.co.uk')
        if settings.USE_TZ:
            tz_utc = pytz.timezone(settings.TIME_ZONE)
            self.assertEqual(data[0].date_begin, datetime(2015, 2, 25, 12, 0, tzinfo=tz_utc))
            self.assertEqual(data[0].date_end, datetime(2015, 2, 26, 12, 0, tzinfo=tz_utc))
        else:
            self.assertEqual(data[0].date_begin, datetime(2015, 2, 25, 12, 0))
            self.assertEqual(data[0].date_end, datetime(2015, 2, 26, 12, 0))
        self.assertEqual(data[0].policy_domain, 'p-o.co.uk')
        self.assertEqual(data[0].policy_adkim, 'r')
        self.assertEqual(data[0].policy_aspf, 'r')
        self.assertEqual(data[0].policy_p, 'quarantine')
        self.assertEqual(data[0].policy_sp, 'none')
        self.assertEqual(data[0].policy_pct, 100)
        self.assertIn("<?xml version='1.0' encoding='utf-8'?>", data[0].report_xml)
        self.assertIn("<feedback>", data[0].report_xml)
        # Record
        data = Record.objects.all()
        self.assertEqual(len(data), 1)
        self.assertEqual(data[0].source_ip, ipaddress.ip_address('80.229.143.200'))
        self.assertEqual(data[0].recordcount, 1)
        self.assertEqual(data[0].policyevaluated_disposition, 'none')
        self.assertEqual(data[0].policyevaluated_dkim, 'pass')
        self.assertEqual(data[0].policyevaluated_spf, 'pass')
        self.assertEqual(data[0].policyevaluated_reasontype, '')
        self.assertEqual(data[0].policyevaluated_reasoncomment, '')
        self.assertEqual(data[0].identifier_headerfrom, 'p-o.co.uk')

        # Result
        data = Result.objects.all()
        self.assertEqual(len(data), 2)
        self.assertEqual(data[0].record_type, 'spf')
        self.assertEqual(data[0].domain, 'p-o.co.uk')
        self.assertEqual(data[0].result, 'pass')
        self.assertEqual(data[1].record_type, 'dkim')
        self.assertEqual(data[1].domain, 'p-o.co.uk')
        self.assertEqual(data[1].result, 'pass')

    def test_importdmarcreport_file_google(self):
        """Test importing an xml file from google"""
        out = StringIO()
        data = Reporter.objects.all()
        self.assertEqual(len(data), 0)
        dmarcreport = os.path.dirname(os.path.realpath(__file__))
        dmarcreport = os.path.join(dmarcreport, 'tests/google.xml')
        call_command('importdmarcreport', '--xml', dmarcreport, stdout=out)
        self.assertIn('', out.getvalue())
        # Reporter object
        data = Reporter.objects.all()
        self.assertEqual(len(data), 1)
        self.assertEqual(data[0].org_name, 'google.com')
        self.assertEqual(data[0].email, 'noreply-dmarc-support@google.com')
        # Report object
        data = Report.objects.all()
        self.assertEqual(len(data), 1)
        self.assertEqual(data[0].report_id, '123456789')
        if settings.USE_TZ:
            tz_utc = pytz.timezone(settings.TIME_ZONE)
            self.assertEqual(data[0].date_begin, datetime(2015, 2, 25, 12, 0, tzinfo=tz_utc))
            self.assertEqual(data[0].date_end, datetime(2015, 2, 26, 12, 0, tzinfo=tz_utc))
        else:
            self.assertEqual(data[0].date_begin, datetime(2015, 2, 25, 12, 0))
            self.assertEqual(data[0].date_end, datetime(2015, 2, 26, 12, 0))
        self.assertEqual(data[0].policy_domain, 'example.net')
        self.assertEqual(data[0].policy_adkim, 'r')
        self.assertEqual(data[0].policy_aspf, 'r')
        self.assertEqual(data[0].policy_p, 'none')
        self.assertEqual(data[0].policy_sp, 'none')
        self.assertEqual(data[0].policy_pct, 100)
        self.assertIn("<?xml version=\"1.0\" encoding=\"UTF-8\" ?>", data[0].report_xml)
        self.assertIn("<feedback>", data[0].report_xml)
        # Record
        data = Record.objects.all()
        self.assertEqual(len(data), 1)
        self.assertEqual(data[0].source_ip, ipaddress.ip_address('2001:DB8::1'))
        self.assertEqual(data[0].recordcount, 2)
        self.assertEqual(data[0].policyevaluated_disposition, 'none')
        self.assertEqual(data[0].policyevaluated_dkim, 'pass')
        self.assertEqual(data[0].policyevaluated_spf, 'pass')
        self.assertEqual(data[0].policyevaluated_reasontype, '')
        self.assertEqual(data[0].policyevaluated_reasoncomment, '')
        self.assertEqual(data[0].identifier_headerfrom, 'lists.example.net')

        # Result
        data = Result.objects.all()
        self.assertEqual(len(data), 2)
        self.assertEqual(data[0].record_type, 'dkim')
        self.assertEqual(data[0].domain, 'example.net')
        self.assertEqual(data[0].result, 'pass')
        self.assertEqual(data[1].record_type, 'spf')
        self.assertEqual(data[1].domain, 'lists.example.net')
        self.assertEqual(data[1].result, 'pass')

    def test_importdmarcreport_file_zip(self):
        """Test importing an email with the xml zipped file"""
        out = StringIO()
        data = Reporter.objects.all()
        self.assertEqual(len(data), 0)

        dmarcreport = os.path.dirname(os.path.realpath(__file__))
        dmarcreport = os.path.join(dmarcreport, 'tests/dmarcreport-email-zip.eml')
        call_command('importdmarcreport', '--email', dmarcreport, stdout=out)
        self.assertIn('', out.getvalue())

        # Reporter object
        data = Reporter.objects.all()

        self.assertEqual(len(data), 1)
        self.assertEqual(data[0].org_name, 'Persistent Objects')
        self.assertEqual(data[0].email, 'ahicks@p-o.co.uk')
        # Report object
        data = Report.objects.all()
        self.assertEqual(len(data), 1)
        self.assertEqual(data[0].report_id, '5edbe461-ccda-1e41-abdb-00c0af3f9715@p-o.co.uk')
        if settings.USE_TZ:
            tz_utc = pytz.timezone(settings.TIME_ZONE)
            self.assertEqual(data[0].date_begin, datetime(2015, 2, 25, 12, 0, tzinfo=tz_utc))
            self.assertEqual(data[0].date_end, datetime(2015, 2, 26, 12, 0, tzinfo=tz_utc))
        else:
            self.assertEqual(data[0].date_begin, datetime(2015, 2, 25, 12, 0))
            self.assertEqual(data[0].date_end, datetime(2015, 2, 26, 12, 0))
        self.assertEqual(data[0].policy_domain, 'p-o.co.uk')
        self.assertEqual(data[0].policy_adkim, 'r')
        self.assertEqual(data[0].policy_aspf, 'r')
        self.assertEqual(data[0].policy_p, 'quarantine')
        self.assertEqual(data[0].policy_sp, 'none')
        self.assertEqual(data[0].policy_pct, 100)
        self.assertIn("<?xml version='1.0' encoding='utf-8'?>", data[0].report_xml)
        self.assertIn("<feedback>", data[0].report_xml)
        # Record
        data = Record.objects.all()
        self.assertEqual(len(data), 1)
        self.assertEqual(data[0].source_ip, ipaddress.ip_address('80.229.143.200'))
        self.assertEqual(data[0].recordcount, 1)
        self.assertEqual(data[0].policyevaluated_disposition, 'none')
        self.assertEqual(data[0].policyevaluated_dkim, 'pass')
        self.assertEqual(data[0].policyevaluated_spf, 'pass')
        self.assertEqual(data[0].policyevaluated_reasontype, '')
        self.assertEqual(data[0].policyevaluated_reasoncomment, '')
        self.assertEqual(data[0].identifier_headerfrom, 'p-o.co.uk')

        # Result
        data = Result.objects.all()
        self.assertEqual(len(data), 2)
        self.assertEqual(data[0].record_type, 'spf')
        self.assertEqual(data[0].domain, 'p-o.co.uk')
        self.assertEqual(data[0].result, 'pass')
        self.assertEqual(data[1].record_type, 'dkim')
        self.assertEqual(data[1].domain, 'p-o.co.uk')
        self.assertEqual(data[1].result, 'pass')

    def test_importdmarcreport_file_duplicate(self):
        """Test importing a duplicate xml file"""
        out = StringIO()
        data = Reporter.objects.all()
        self.assertEqual(len(data), 0)

        dmarcreport = os.path.dirname(os.path.realpath(__file__))
        dmarcreport = os.path.join(dmarcreport, 'tests/dmarcreport-email-gz.eml')
        call_command('importdmarcreport', '--email', dmarcreport, stdout=out)
        self.assertIn('', out.getvalue())

        # Reporter object
        data = Reporter.objects.all()
        self.assertEqual(len(data), 1)
        self.assertEqual(data[0].org_name, 'Persistent Objects')
        self.assertEqual(data[0].email, 'ahicks@p-o.co.uk')

        # Report object
        data = Report.objects.all()
        self.assertEqual(len(data), 1)

        dmarcreport = os.path.dirname(os.path.realpath(__file__))
        dmarcreport = os.path.join(dmarcreport, 'tests/duplicate_report.eml')
        call_command('importdmarcreport', '--email', dmarcreport, stdout=out)
        self.assertIn('', out.getvalue())

        # should still be one of each
        data = Reporter.objects.all()
        self.assertEqual(len(data), 1)

        # Report object
        data = Report.objects.all()
        self.assertEqual(len(data), 1)

    def test_importdmarcreport_file_large_gz(self):
        """Test importing email with large gzip file"""
        out = StringIO()
        dmarcreport = os.path.dirname(os.path.realpath(__file__))
        dmarcreport = os.path.join(dmarcreport, 'tests/email-large-gz.eml')
        msg = ''
        try:
            call_command(
                'importdmarcreport',
                '--email',
                dmarcreport,
                stdout=out)
        except CommandError as cmderr:
            msg = str(cmderr)
        self.assertIn("decompression exceeded limit on gzipfile", msg)

    def test_importdmarcreport_file_large_zip(self):
        """Test importing email with large zip file"""
        out = StringIO()
        dmarcreport = os.path.dirname(os.path.realpath(__file__))
        dmarcreport = os.path.join(dmarcreport, 'tests/email-large-zip.eml')
        msg = ""
        try:
            call_command(
                'importdmarcreport',
                '--email',
                dmarcreport,
                stdout=out)
        except CommandError as cmderr:
            msg = str(cmderr)
        self.assertIn("skipping oversized file", msg)


class ImportDMARCFeedbackTestCase(TestCase):
    """
    Test importing feedback reports
    """

    def test_feedback_import_noargs(self):
        """Test importing a feedback report without args"""
        msg = 'Check usage, please supply a single DMARC feedback report email'
        out = StringIO()
        try:
            call_command('importdmarcfeedback', stdout=out)
        except CommandError as cmderror:
            msgerror = str(cmderror)
        self.assertIn(msg, msgerror)

    # feedback.eml is from:
    # https://github.com/sisimai/p5-sisimai/blob/master/set-of-emails/maildir/bsd/arf-16.eml
    def test_feedback_import_actually_abuse(self):
        """Test importing a feedback report thats an abuse report, not a DMARC feedback report"""

        msgerror = None

        dmarcfeedback = os.path.dirname(os.path.realpath(__file__))
        dmarcfeedback = os.path.join(dmarcfeedback, 'tests/feedback.eml')
        try:
            call_command(
                'importdmarcfeedback',
                '--email',
                dmarcfeedback)
        except CommandError as cmderror:
            msgerror = str(cmderror)
            print(msgerror)

        # We should not have any objects for this report
        data = FBReporter.objects.all()
        self.assertEqual(len(data), 0)
        # Report object
        data = FBReport.objects.all()
        self.assertEqual(len(data), 0)

    # feedback2.eml is from:
    # https://github.com/scottgifford/bouncehammer/blob/master/t/041_mta-feedbackloop.t
    def test_feedback_import_also_actually_abuse(self):
        """Test importing a feedback report thats an abuse report, not a DMARC feedback report"""
        out = StringIO()

        dmarcfeedback = os.path.dirname(os.path.realpath(__file__))
        dmarcfeedback = os.path.join(dmarcfeedback, 'tests/feedback2.eml')
        try:
            call_command(
                'importdmarcfeedback',
                '--email',
                dmarcfeedback,
                stdout=out)
        except CommandError as cmderror:
            msgerror = str(cmderror)
            print(msgerror)
        self.assertIn('', out.getvalue())

        # We should not have any objects for this report
        data = FBReporter.objects.all()
        self.assertEqual(len(data), 0)
        # Report object
        data = FBReport.objects.all()
        self.assertEqual(len(data), 0)

    # feedback3 is right(?)
    # feedback3.eml is from:
    # https://github.com/sisimai/p5-sisimai/blob/master/set-of-emails/maildir/bsd/arf-18.eml
    def test_feedback_import(self):
        """Test importing a DMARC feedback report"""
        out = StringIO()

        dmarcfeedback = os.path.dirname(os.path.realpath(__file__))
        dmarcfeedback = os.path.join(dmarcfeedback, 'tests/feedback3.eml')
        try:
            call_command(
                'importdmarcfeedback',
                '--email',
                dmarcfeedback,
                stdout=out)
        except CommandError as cmderror:
            msgerror = str(cmderror)
            print(msgerror)
        self.assertIn('', out.getvalue())

        # We should not have any objects for this report
        data = FBReporter.objects.all()
        self.assertEqual(len(data), 1)
        # Report object
        data = FBReport.objects.all()
        self.assertEqual(len(data), 1)

    # feedback4 is wrong for us - it's a DKIM failure
    # feedback4.eml is from:
    # https://tools.ietf.org/html/rfc6591#page-14
    def test_feedback_import_also_actually_dkim(self):
        """Test importing a feedback report thats a DKIM failure report, not a DMARC feedback report"""
        out = StringIO()

        dmarcfeedback = os.path.dirname(os.path.realpath(__file__))
        dmarcfeedback = os.path.join(dmarcfeedback, 'tests/feedback4.eml')
        try:
            call_command(
                'importdmarcfeedback',
                '--email',
                dmarcfeedback,
                stdout=out)
        except CommandError as cmderror:
            msgerror = str(cmderror)
            print(msgerror)
        self.assertIn('', out.getvalue())

        # We should not have any objects for this report
        data = FBReporter.objects.all()
        self.assertEqual(len(data), 0)
        # Report object
        data = FBReport.objects.all()
        self.assertEqual(len(data), 0)

# Might also want to look at:
# https://github.com/rjbs/Email-ARF/blob/master/t/messages/example2.msg
#
# https://github.com/sisimai/p5-sisimai/blob/master/set-of-emails/maildir/bsd/arf-19.eml
# https://github.com/fritids/Bisons-RFC-Theme/blob/master/bouncehandler/eml/arf3.txt
# https://github.com/andrzejdziekonski/PHPMailer-BMH/blob/master/test/fixtures/PHP-Bounce-Handler/arf3.txt
# https://github.com/danielsen/arf/blob/master/test/resources/sample_arf_message.txt
#
#
# Maybe use this?:
# https://github.com/danielsen/arf


class DMARCViewTests(TestCase):
    """Test our views"""

    def setUp(self):
        self.user = User.objects.create_user(username='user', password='pass')
        self.user.save()

        self.staffuser = User.objects.create_user(username='staffuser', password='pass')
        self.staffuser.is_staff = True
        self.staffuser.save()

    def import_xml_file(self):
        """Import an xml file to populate the database"""
        out = StringIO()
        dmarcreport = os.path.dirname(os.path.realpath(__file__))
        dmarcreport = os.path.join(dmarcreport, 'tests/dmarcreport.xml')
        call_command('importdmarcreport', '--xml', dmarcreport, stdout=out)

    def test_main_view(self):
        # can't be an anon user
        response = self.client.get(reverse('dmarc:dmarc_report'))
        self.assertEqual(response.status_code, 302)
        self.assertTrue(response.url.startswith(reverse('admin:login')))

        # and can't be a normal user
        self.client.login(username='user', password='pass')
        response = self.client.get(reverse('dmarc:dmarc_report'))
        self.assertEqual(response.status_code, 302)
        self.assertTrue(response.url.startswith(reverse('admin:login')))

        self.client.logout()

        self.client.login(username='staffuser', password='pass')
        response = self.client.get(reverse('dmarc:dmarc_report'))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "DMARC aggregate feedback report")

    def test_csv_view(self):
        response = self.client.get(reverse('dmarc:dmarc_csv'))
        self.assertEqual(response.status_code, 302)
        self.assertTrue(response.url.startswith(reverse('admin:login')))

        self.client.login(username='staffuser', password='pass')

        response = self.client.get(reverse('dmarc:dmarc_csv'))
        self.assertEqual(response.status_code, 200)

        rc = ""
        for r in response.streaming_content:
            rc += r.decode("utf-8")
        # XXX maybe instead of an empty file we should just return column
        # headers?
        self.assertEqual(len(rc), 0)

        self.import_xml_file()
        response = self.client.get(reverse('dmarc:dmarc_csv'))
        self.assertEqual(response.status_code, 200)

        rc = ""
        for r in response.streaming_content:
            rc += r.decode("utf-8")

        self.assertTrue("5edbe461-ccda-1e41-abdb-00c0af3f9715" in rc)
        self.assertEqual(len(rc.split("\n")), 3)

    def test_json_view(self):
        response = self.client.get(reverse('dmarc:dmarc_json'))
        self.assertEqual(response.status_code, 302)
        self.assertTrue(response.url.startswith(reverse('admin:login')))

        self.client.login(username='staffuser', password='pass')

        response = self.client.get(reverse('dmarc:dmarc_json'))
        self.assertEqual(response.status_code, 200)

        self.assertEqual(response.content.decode(), '[]')

        self.import_xml_file()
        response = self.client.get(reverse('dmarc:dmarc_json'))
        self.assertEqual(response.status_code, 200)

        self.assertContains(response, "5edbe461-ccda-1e41-abdb-00c0af3f9715")
