# ----------------------------------------------------------------------
# Copyright (c) 2015-2019, Persistent Objects Ltd http://p-o.co.uk/
#
# License: BSD
# ----------------------------------------------------------------------
"""Import DMARC Aggregate Reports"""

import difflib
import logging
import os
import tempfile
import zipfile
import zlib
from argparse import FileType
from datetime import datetime
from email import message_from_string
from io import BytesIO

import defusedxml.ElementTree as ET
import pytz
from django.core.exceptions import ObjectDoesNotExist
from django.core.management.base import BaseCommand, CommandError
from django.db import Error, transaction
from django.db.utils import IntegrityError
from lxml import etree

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

        ret = self.validate_dmarc_xml(dmarc_xml)
        if 'result' not in ret:
            msg = "Unknown result trying to validate xml file"
            logger.error(msg)
            raise CommandError(msg)

        if ret['result'] != 'pass':
            msg = "failed to validate xml file: %s" % (ret['info'])
            logger.error(msg)
            raise CommandError(msg)

        tz_utc = pytz.timezone('UTC')
        try:
            root = ET.fromstring(dmarc_xml)
        except Exception:
            msg = ""
            if len(dmarc_xml) > 5000 or len(email) > 4000:
                msg = "Processing xml failed (with large files)"
            else:
                msg = "Processing xml failed:\n {}\n//\n{}".format(dmarc_xml, email)
            logger.exception(msg)
            return

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
            except Error:
                msg = "Unable to create DMARC report for {}".format(org_name)
                logger.exception(msg)

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
        except Exception:
            msg = "Unable to understand DMARC reporting dates"
            logger.exception(msg)
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
            with transaction.atomic():
                report.save()
        except IntegrityError:
            msg = "DMARC duplicate report record"
            logger.exception(msg)
            msg = "{} // {} // {}".format(report.reporter, report.report_id, report.date_begin)
            logger.error(msg)
            msg = "org: {}, email: {}".format(reporter.org_name, reporter.email)
            logger.error(msg)

            prev_report = Report.objects.get(report_id=report.report_id)

            prev = prev_report.report_xml
            this = dmarc_xml

            if prev != this:
                logger.error("**** prev report ****")
                logger.error(prev)
                logger.error("**** this report ****")
                logger.error(this)
                logger.error("****    diff     ****")
                a = prev.split("\n")
                b = this.split("\n")
                diff = difflib.unified_diff(a, b, fromfile='previous_report.xml', tofile='this_report.xml')
                o = ""
                for d in diff:
                    if d.endswith("\n"):
                        o += d
                    else:
                        o += d + "\n"
                logger.error(o)
            return
        except Error:
            msg = "Unable to save the DMARC report header {}".format(report_id)
            logger.exception(msg)

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
            except IntegrityError:
                msg = "DMARC duplicate record"
                logger.exception(msg)
            except Error:
                msg = "Unable to save the DMARC report record"
                logger.exception(msg)

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
                except Error:
                    msg = "Unable to save the DMARC report result {} for {}".format(
                        resulttype.tag,
                        result_domain,
                    )
                    logger.exception(msg)
        if ok_records == 0:
            msg = "didn't get any usable records, deleteing the report"
            logger.error(msg)
            report.delete()

    @staticmethod
    def validate_dmarc_xml(dmarc_xml):
        """Validate the XML"""
        # taken from:
        # https://github.com/jorritfolmer/TA-dmarc/blob/master/bin/dmarc/dir2splunk.py#L403
        logger = logging.getLogger(__name__)

        xsdfilelist = ["rua_ta_dmarc_relaxed_v01.xsd",
                       "rua_draft-dmarc-base-00-02.xsd",
                       "rua_rfc7489.xsd",
                       "rua_ta_dmarc_minimal_v01.xsd"]
        # this one seems to work ok
        # but need to check the spf/dkim order in auth_result
        xsdfile = xsdfilelist[0]
        dmarc_path = os.path.dirname(__file__)
        info = {}

        xsdfile_long = os.path.join(dmarc_path, xsdfile)

        # Read XML and XSD files
        try:
            xmldata = dmarc_xml.encode("utf-8")
            xsddata = open(xsdfile_long, 'r').read()
        except Exception as e:
            logger.warning("validate_dmarc_xml: error opening with %s" % str(e))
            info["result"] = "fail"
            info["info"] = "%s" % str(e)
            return info

        # Parse the XML and XSD
        try:
            xml = etree.XML(xmldata)
            xsd = etree.XML(xsddata)
            xmlschema = etree.XMLSchema(xsd)
        except Exception as e:
            logger.warning("validate_xml_xsd: xml parse error with %s" % (str(e)))
            info["result"] = "fail"
            info["info"] = "%s" % str(e)
            return info

        # Validate XML against XSD
        try:
            xmlschema.assertValid(xml)
        except Exception as e:
            logger.debug(
                "validate_xml_xsd: xsd validation failed against %s with %s" % (xsdfile, str(e)))
            info["result"] = "fail"
            info["info"] = "%s" % str(e)
            return info
        else:
            logger.debug("validate_xml_xsd: xsd validation successful against %s" % (xsdfile))
            info["result"] = "pass"
            return info

        return {}

    @staticmethod
    def get_xml_from_email(email):
        """Get xml from an email"""
        # pylint: disable=too-many-statements
        dmarc_xml = ''
        # XXX maybe put in settings?
        max_xml_file_size = 100000000
        logger = logging.getLogger(__name__)

        msg = 'Processing email'
        logger.debug(msg)
        try:
            dmarcemail = message_from_string(email)
        except Exception:
            msg = 'Unable to use email'
            logger.exception(msg)
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
                            if file_.file_size < max_xml_file_size and file_.filename.endswith("xml"):
                                dmarc_xml = archive.read(file_)
                            elif file_.file_size >= max_xml_file_size and file_.filename.endswith("xml"):
                                msg = "skipping oversized file %s of size %d" % (file_.filename, file_.file_size)
                                logger.error(msg)
                                raise CommandError(msg)
                            else:
                                msg = "skipping non-XML file %s of size %d" % (file_.filename, file_.file_size)
                                logger.error(msg)
                                raise CommandError(msg)
                        archive.close()
                    except zipfile.BadZipfile:
                        msg = 'Unable to unzip mimepart'
                        logger.exception(msg)
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
                    zobj = zlib.decompressobj(zlib.MAX_WBITS | 32)
                    try:
                        data = dmarc_zip.read()
                        # Protect against gzip bombs by limiting decompression to max_size
                        dmarc_xml = zobj.decompress(data, max_xml_file_size)
                        data = None
                        msg = "DMARC successfully extracted xml from gzip"
                        logger.debug(msg)
                    except Exception:
                        msg = 'Unable to gunzip mimepart'
                        logger.exception(msg)
                        temp = tempfile.mkstemp(prefix='dmarc-', suffix='.gz')
                        dmarc_zip.seek(0)
                        tmpf = os.fdopen(temp[0], 'w')
                        tmpf.write(dmarc_zip.getvalue())
                        tmpf.close()
                        msg = 'Saved in: {}'.format(temp[1])
                        logger.debug(msg)
                        raise CommandError(msg)
                    else:
                        if zobj.unconsumed_tail:
                            del zobj
                            del dmarc_xml
                            del dmarc_zip
                            msg = "decompression exceeded limit on gzipfile"
                            logger.error(msg)
                            raise CommandError(msg)
            else:
                try:
                    myname = mimepart.get_filename()
                except Exception:
                    myname = 'Not able to find part filename'
                    logger.exception(myname)
                msg = "DMARC Report is not in mimepart: {}".format(myname)
                logger.debug(msg)

        if not isinstance(dmarc_xml, str):
            dmarc_xml = dmarc_xml.decode("utf-8")
        return dmarc_xml
