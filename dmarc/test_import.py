# ----------------------------------------------------------------------
# Copyright (c) 2015-2019, Persistent Objects Ltd http://p-o.co.uk/
#
# License: BSD
# ----------------------------------------------------------------------
"""
DMARC tests for importing Aggregate Reports
https://dmarc.org/resources/specification/
"""
import os
from datetime import datetime
from io import StringIO

import pytz
from django.conf import settings
from django.core.management import call_command
from django.core.management.base import CommandError
from django.test import TestCase

from dmarc.models import Record, Report, Reporter, Result


class ImportDMARCReportTestCase(TestCase):
    """
    Standard core tests
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
        self.assertEqual(data[0].source_ip, '80.229.143.200')
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

# feedback.eml is from:
# https://github.com/sisimai/p5-sisimai/blob/master/set-of-emails/maildir/bsd/arf-16.eml
#
# feedback2.eml is from:
# https://github.com/scottgifford/bouncehammer/blob/master/t/041_mta-feedbackloop.t
#

# feedback3.eml is from:
# https://github.com/sisimai/p5-sisimai/blob/master/set-of-emails/maildir/bsd/arf-18.eml

# feedback4.eml is from:
# https://tools.ietf.org/html/rfc6591#page-14

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
