# ----------------------------------------------------------------------
# Copyright (c) 2015-2019, Persistent Objects Ltd http://p-o.co.uk/
#
# License: BSD
# ----------------------------------------------------------------------
"""Import DMARC Aggregate Reports"""
from __future__ import unicode_literals

import difflib
import gzip
import logging
import os
import tempfile
import xml.etree.ElementTree as ET
import zipfile
from argparse import FileType
from datetime import datetime
from email import message_from_string

import pytz
from django.core.exceptions import ObjectDoesNotExist
from django.core.management.base import BaseCommand, CommandError
from django.db import Error
from django.db.utils import IntegrityError
from six import BytesIO

from dmarc.models import Record, Report, Reporter, Result


class Command(BaseCommand):
    """
    Command class for importing DMARC Aggregate Reports
    Most errors are not raised to prevent email bounces
    """
    help = 'Imports a DMARC Aggregate Report from either email or xml'

    def add_arguments(self, parser):
        parser.add_argument(
            '-e',
            '--email',
            type=FileType('r'),
            default=False,
            help='Import from email file, or - for stdin'
        )
        parser.add_argument(
            '-x',
            '--xml',
            type=FileType('r'),
            default=False,
            help='Import from xml file, or - for stdin'
        )

    def handle(self, *args, **options):
        """
        Handle method to import a DMARC Aggregate Reports
        Either pass in
        - the email message and the DMARC XML data will be extracted;
        - or the xml file.
        """
        # pylint: disable=too-many-branches,too-many-locals,too-many-statements
        logger = logging.getLogger(__name__)
        logger.info("Importing DMARC Aggregate Reports")

        dmarc_xml = ''

        email = None

        if options['email']:
            email = options['email'].read()
            msg = 'Importing from email: {}'.format(email)
            dmarc_xml = self.get_xml_from_email(email)
        elif options['xml']:
            dmarc_xml = options['xml'].read()
            msg = 'Importing from xml: {}'.format(dmarc_xml)
            logger.debug(msg)
        else:
            msg = "Check usage, please supply a single DMARC report file or email"
            logger.error(msg)
            raise CommandError(msg)

        tz_utc = pytz.timezone('UTC')
        try:
            root = ET.fromstring(dmarc_xml)
        except:
            msg = "Processing xml failed: {} // {}".format(dmarc_xml, email)
            logger.error(msg)
            return

        orig_email = email

        # Report metadata
        report_metadata = root.findall('report_metadata')
        org_name = None
        email = None
        report_id = None
        report_begin = None
        report_end = None
        for node in report_metadata[0]:
            if node.tag == 'org_name':
                org_name = node.text
            if node.tag == 'email':
                email = node.text
            if node.tag == 'report_id':
                report_id = node.text
            if node.tag == 'date_range':
                report_begin = node.find('begin').text
                report_end = node.find('end').text

        if org_name is None:
            msg = "This DMARC report does not have an org_name"
            logger.error(msg)
        if report_id is None:
            msg = "This DMARC report for {} does not have a report_id".format(org_name)
            logger.error(msg)
        try:
            reporter = Reporter.objects.get(org_name=org_name)
        except ObjectDoesNotExist:
            try:
                reporter = Reporter.objects.create(org_name=org_name, email=email)
            except Error as err:
                msg = "Unable to create DMARC report for {}: {}".format(org_name, err)
                logger.error(msg)

        # Reporting policy
        policy_published = root.findall('policy_published')
        # Set defaults
        policy_domain = None
        policy_adkim = 'r'
        policy_aspf = 'r'
        policy_p = 'none'
        policy_sp = 'none'
        policy_pct = 0
        for node in policy_published[0]:
            if node.tag == 'domain':
                policy_domain = node.text
            if node.tag == 'adkim':
                policy_adkim = node.text
            if node.tag == 'aspf':
                policy_aspf = node.text
            if node.tag == 'p':
                policy_p = node.text
            if node.tag == 'sp':
                policy_sp = node.text
            if node.tag == 'pct':
                policy_pct = int(node.text)

        # Create the report
        report = Report()
        report.report_id = report_id
        report.reporter = reporter
        report_date_begin = datetime.fromtimestamp(float(report_begin)).replace(tzinfo=tz_utc)
        try:
            report_date_begin = datetime.fromtimestamp(float(report_begin)).replace(tzinfo=tz_utc)
            report_date_end = datetime.fromtimestamp(float(report_end)).replace(tzinfo=tz_utc)
        except:
            msg = "Unable to understand DMARC reporting dates"
            logger.error(msg)
        report.date_begin = report_date_begin
        report.date_end = report_date_end
        report.policy_domain = policy_domain
        report.policy_adkim = policy_adkim
        report.policy_aspf = policy_aspf
        report.policy_p = policy_p
        report.policy_sp = policy_sp
        report.policy_pct = policy_pct
        report.report_xml = dmarc_xml
        try:
            report.save()
        except IntegrityError as err:
            msg = "DMARC duplicate report record: {}".format(err)
            logger.error(msg)
            msg = "{} // {} // {}".format(report.reporter, report.report_id, report.date_begin)
            logger.error(msg)
            msg = "org: {}, email: {}".format(reporter.org_name, reporter.email)
            logger.error(msg)

            prev_report = Report.objects.get(report_id=report.report_id)
            xml_str = dmarc_xml.decode("utf-8")
            if prev_report.report_xml != xml_str:
                logger.error("**** prev report ****")
                logger.error(prev_report.report_xml)
                logger.error("**** this report ****")
                logger.error(xml_str)
                logger.error("****    diff     ****")
                a = prev_report.report_xml.split("\n")
                b = xml_str.split("\n")
                diff = difflib.unified_diff(a, b, fromfile='previous_report.xml', tofile='this_report.xml')
                o = ""
                for d in diff:
                    if d.endswith("\n"):
                        o += d
                    else:
                        o += d + "\n"
                logger.error(o)
            return
        except Error as err:
            msg = "Unable to save the DMARC report header {}: {}".format(report_id, err)
            logger.error(msg)

        ok_records = 0
        # Record
        for node in root.findall('record'):
            source_ip = None
            recordcount = 0
            policyevaluated_disposition = None
            policyevaluated_dkim = None
            policyevaluated_spf = None
            policyevaluated_reasontype = ''
            policyevaluated_reasoncomment = ''
            identifier_headerfrom = None
            row = node.find('row')
            source_ip = row.find('source_ip').text
            if row.find('count') is not None:
                recordcount = int(row.find('count').text)
            else:
                recordcount = 0
            policyevaluated = row.find('policy_evaluated')
            policyevaluated_disposition = policyevaluated.find('disposition').text
            policyevaluated_dkim = policyevaluated.find('dkim').text
            policyevaluated_spf = policyevaluated.find('spf').text
            if policyevaluated.find('reason') is not None:
                reason = policyevaluated.find('reason')
                if reason.find('type') is not None:
                    policyevaluated_reasontype = reason.find('type').text
                if reason.find('comment') is not None:
                    if reason.find('comment').text is not None:
                        policyevaluated_reasoncomment = reason.find('comment').text

            identifiers = node.find('identifiers')
            identifier_headerfrom = identifiers.find('header_from').text

            if not source_ip:
                msg = "DMARC report record useless without a source ip"
                logger.error(msg)
                continue

            # Create the record
            record = Record()
            record.report = report
            record.source_ip = source_ip
            record.recordcount = recordcount
            record.policyevaluated_disposition = policyevaluated_disposition
            record.policyevaluated_dkim = policyevaluated_dkim
            record.policyevaluated_spf = policyevaluated_spf
            record.policyevaluated_reasontype = policyevaluated_reasontype
            record.policyevaluated_reasoncomment = policyevaluated_reasoncomment
            record.identifier_headerfrom = identifier_headerfrom
            try:
                record.save()
                ok_records += 1
            except IntegrityError as err:
                msg = "DMARC duplicate record: {}".format(err)
                logger.error(msg)
            except Error as err:
                msg = "Unable to save the DMARC report record: {}".format(err)
                logger.error(msg)

            auth_results = node.find('auth_results')
            for resulttype in auth_results:
                result_domain = resulttype.find('domain').text
                if result_domain is None:
                    # Allow for blank domains
                    result_domain = ''
                result_result = resulttype.find('result').text

                # Create the record
                result = Result()
                result.record = record
                result.record_type = resulttype.tag
                result.domain = result_domain
                result.result = result_result
                try:
                    result.save()
                    ok_records += 1
                except Error as err:
                    msg = "Unable to save the DMARC report result {} for {}: {}".format(
                        resulttype.tag,
                        result_domain,
                        err.message
                    )
                    logger.error(msg)
        if ok_records == 0:
            msg = "didn't get any usable records, deleteing the report"
            logger.error(msg)
            report.delete()

    @staticmethod
    def get_xml_from_email(email):
        """Get xml from an email"""
        # pylint: disable=too-many-statements
        dmarc_xml = ''
        logger = logging.getLogger(__name__)

        msg = 'Processing email'
        logger.debug(msg)
        try:
            dmarcemail = message_from_string(email)
        except:
            msg = 'Unable to use email'
            logger.debug(msg)
            return ''

        for mimepart in dmarcemail.walk():
            msg = 'Processing content type: {}'.format(mimepart.get_content_type())
            logger.debug(msg)
            if mimepart.get_content_type() in (
                    'application/x-zip-compressed',
                    'application/x-zip',
                    'application/zip',
                    'application/gzip',
                    'application/octet-stream',
                    'text/plain'
            ):
                # zoho.com uses text/plain for zip files :/
                if mimepart.get_content_type() == 'text/plain':
                    if not mimepart.get_filename('').endswith('.zip'):
                        continue
                dmarc_zip = BytesIO()
                dmarc_zip.write(mimepart.get_payload(decode=True))
                dmarc_zip.seek(0)
                if zipfile.is_zipfile(dmarc_zip):
                    msg = "DMARC is zipfile"
                    logger.debug(msg)
                    try:
                        archive = zipfile.ZipFile(dmarc_zip, 'r')
                        files = archive.infolist()
                        # The DMARC report should only contain a single xml file
                        for file_ in files:
                            dmarc_xml = archive.read(file_)
                        archive.close()
                    except zipfile.BadZipfile:
                        msg = 'Unable to unzip mimepart'
                        logger.error(msg)
                        temp = tempfile.mkstemp(prefix='dmarc-', suffix='.zip')
                        dmarc_zip.seek(0)
                        tmpf = os.fdopen(temp[0], 'w')
                        tmpf.write(dmarc_zip.getvalue())
                        tmpf.close()
                        msg = 'Saved in: {}'.format(temp[1])
                        logger.debug(msg)
                        raise CommandError(msg)
                else:
                    msg = "DMARC trying gzip"
                    logger.debug(msg)
                    # Reset zip file
                    dmarc_zip.seek(0)
                    try:
                        archive = gzip.GzipFile(None, 'rb', 0, dmarc_zip)
                        dmarc_xml = archive.read()
                        archive = None
                        msg = "DMARC successfully extracted xml from gzip"
                        logger.debug(msg)
                    except:
                        msg = 'Unable to gunzip mimepart'
                        logger.error(msg)
                        temp = tempfile.mkstemp(prefix='dmarc-', suffix='.gz')
                        dmarc_zip.seek(0)
                        tmpf = os.fdopen(temp[0], 'w')
                        tmpf.write(dmarc_zip.getvalue())
                        tmpf.close()
                        msg = 'Saved in: {}'.format(temp[1])
                        logger.debug(msg)
                        raise CommandError(msg)
            else:
                try:
                    myname = mimepart.get_filename()
                except:
                    myname = 'Not provided'
                msg = "DMARC Report is not in mimepart: {}".format(myname)
                logger.debug(msg)
        return dmarc_xml
