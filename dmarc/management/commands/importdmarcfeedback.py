# ----------------------------------------------------------------------
# Copyright (c) 2015-2019, Persistent Objects Ltd http://p-o.co.uk/
#
# License: BSD
# ----------------------------------------------------------------------
"""Import DMARC Feedback Reports"""

import logging
import os
import tempfile
from argparse import FileType
from datetime import datetime
from email import message_from_string
from email.generator import Generator
from email.utils import mktime_tz, parsedate_tz
from io import StringIO

import pytz
from django.core.exceptions import ObjectDoesNotExist
from django.core.management.base import BaseCommand, CommandError

from dmarc.models import FBReport, FBReporter

logger = logging.getLogger(__name__)


class Command(BaseCommand):
    """
    Command class for importing DMARC Feedback Reports
    Most errors are not raised to prevent email bounces
    """

    help = "Imports a DMARC Feedback Report from an email"

    def add_arguments(self, parser):
        parser.add_argument(
            "-e",
            "--email",
            type=FileType("r"),
            default=False,
            help="Import from email file, or - for stdin",
        )

    def handle(self, *args, **options):
        """
        Handle method to import a DMARC Feedback Report
        """

        logger.info("Importing DMARC Feedback Report")

        if not options["email"]:
            msg = "Check usage, please supply a single DMARC feedback report email"
            logger.error(msg)
            raise CommandError(msg)

        msg = "Processing email"
        logger.debug(msg)

        try:
            email = options["email"].read()
            dmarcemail = message_from_string(email)
        except Exception:
            msg = "Unable to use email"
            logger.exception(msg)
            raise CommandError(msg)

        if dmarcemail.is_multipart():
            self.process_multipart(dmarcemail)
        else:
            self.process_822(dmarcemail)

    @staticmethod
    def save_email(dmarcemail):
        temp = tempfile.mkstemp(prefix="dmarc-", suffix=".eml")
        tmpf = os.fdopen(temp[0], "wb")
        tmpf.write(bytes(dmarcemail))
        tmpf.close()
        msg = "Saved as: {}".format(temp[1])
        logger.error(msg)
        raise CommandError(msg)

    @staticmethod
    def process_multipart(dmarcemail):
        """Extract multipart report"""
        # pylint: disable=too-many-branches,too-many-locals,too-many-statements
        # pylint: disable=too-many-nested-blocks

        # Get the human readable part
        try:
            mimepart = dmarcemail.get_payload(0)
            if mimepart.get_content_type() != "text/plain":
                raise ValueError("Wrong mime type for the first mime part")

            mimepart = dmarcemail.get_payload(1)
            if mimepart.get_content_type() != "message/feedback-report":
                raise ValueError("Wrong mime type for the second mime part")

            mimepart = dmarcemail.get_payload(2)
            if mimepart.get_content_type() not in (
                "message/rfc822",
                "text/rfc822-headers",
                "message/rfc822-headers",
                "text/rfc822",
            ):
                raise ValueError("Wrong mime type for the third mime part")

        except Exception:
            msg = "Mime-Types checking"
            logger.exception(msg)
            Command.save_email(dmarcemail)

        report = FBReport()
        dmarc_reporter = None
        try:
            dmarc_reporter = dmarcemail.get("from")
            report.reporter = FBReporter.objects.get(email=dmarc_reporter)
            mimepart = dmarcemail.get_payload()
        except ObjectDoesNotExist:
            try:
                report.reporter = FBReporter(
                    org_name=dmarc_reporter, email=dmarc_reporter,
                )
            except Exception:
                msg = "Failed to find or create reporter {}".format(dmarc_reporter)
                logger.exception(msg)
                raise CommandError(msg)
        except Exception:
            msg = "Unable to get rfc822 report"
            logger.exception(msg)
            Command.save_email(dmarcemail)

        out = StringIO()
        gen = Generator(out, maxheaderlen=0)
        gen.flatten(dmarcemail)
        report.feedback_source = out.getvalue()
        gen = None
        out = None

        try:
            # Get the human readable part
            mimepart = dmarcemail.get_payload(0)
            # get the human-readable part of the message
            report.description = mimepart
        except Exception:
            msg = "Unable to get human readable part"
            logger.exception(msg)
            raise CommandError(msg)

        # Get the feedback report
        reportpart = None
        try:
            mimepart = dmarcemail.get_payload(1)
            reportpart = mimepart
            out = StringIO()
            gen = Generator(out, maxheaderlen=0)
            gen.flatten(mimepart)
            report.feedback_report = out.getvalue()
            gen = None
            out = None
        except Exception:
            msg = "Unable to get feedback-report part"
            logger.exception(msg)
            Command.save_email(dmarcemail)

        # should check for:
        # Feedback-Type: auth-failure
        # Auth-Failure: dmarc
        # ... or something like that,
        # see: https://tools.ietf.org/html/rfc7489#page-36

        if report.feedback_report and reportpart:
            first = False
            headers = {}
            for p in reportpart.walk():
                if not first:
                    first = True
                else:
                    # XXX this mangles multiple
                    # keys with different values
                    for k in p.keys():
                        # print(k, p[k])
                        if k not in headers:
                            headers[k] = [
                                p[k],
                            ]
                        else:
                            headers[k].append(p[k])

            # print(headers)

            if "Feedback-Type" not in headers or "Auth-Failure" not in headers:
                logger.error("Probably not a DMARC feedback email, missing headers")
                Command.save_email(dmarcemail)

            if headers["Feedback-Type"][0] != "auth-failure":
                logger.error(
                    "Probably not a DMARC feedback email, not an auth-failure message: {}".format(
                        headers["Feedback-Type"][0]
                    )
                )
                Command.save_email(dmarcemail)

            if headers["Auth-Failure"][0] != "dmarc":
                logger.error(
                    "Probably not a DMARC feedback email, auth-failure wasn't dmarc: {}".format(
                        headers["Auth-Failure"][0]
                    )
                )
                Command.save_email(dmarcemail)

            if "Reported-Domain" in headers:
                report.domain = headers["Reported-Domain"][0]
            if "Source-IP" in headers:
                report.source_ip = headers["Source-IP"][0]
            if "Original-Mail-From" in headers:
                report.email_from = headers["Original-Mail-From"][0]
            if "Arrival-Date" in headers:
                arrival_date = headers["Arrival-Date"][0]
                try:
                    # get tuples
                    tuples = parsedate_tz(arrival_date)
                    # get timestamp
                    time = mktime_tz(tuples)
                    report.date = datetime.fromtimestamp(time)
                    tz_utc = pytz.timezone("UTC")
                    report.date = report.date.replace(tzinfo=tz_utc)
                except Exception:
                    msg = "Unable to get date from: {}".format(arrival_date)
                    logger.exception(msg)
                    report.date = datetime.now()

            if "Delivery-Result" in headers:
                report.dmarc_result = headers["Delivery-Result"][0]
            if "Authentication-Results" in headers:
                auth_results = headers["Authentication-Results"][0].split()
                for result in auth_results:
                    (typ, eq_sign, alignment) = result.partition("=")
                    if not eq_sign:
                        continue
                    if not report.dkim_alignment and typ == "dkim":
                        report.dkim_alignment = alignment.rstrip(";")
                    if not report.spf_alignment and typ == "spf":
                        report.spf_alignment = alignment.rstrip(";")

        # Get the rfc822 headers and any message
        out = StringIO()
        gen = Generator(out, maxheaderlen=0)
        try:
            mimepart = dmarcemail.get_payload(2)
            gen.flatten(mimepart)
            report.email_source = out.getvalue()
        except Exception:
            msg = "Unable to get rfc822 part"
            logger.exception(msg)
            Command.save_email(dmarcemail)
        gen = None
        out = None
        if report.email_source:
            # XXX also use the header parser part of the email module here.
            for line in report.email_source.splitlines():
                line = line.lstrip()
                (ls0, ls1, ls2) = line.partition(":")
                ls0 = ls0.strip()
                ls2 = ls2.strip()
                if ls1:
                    if not report.email_subject:
                        if ls0 == "Subject":
                            report.email_subject = ls2
        try:
            reporter = report.reporter
            reporter.save()
            report.reporter = reporter
            report.save()
        except Exception:
            msg = "Failed save from {}".format(report.reporter)
            logger.exception(msg)
            Command.save_email(dmarcemail)

    # XXX not needed??
    @staticmethod
    def process_822(dmarcemail):
        """Extract report from rfc822 email, non standard"""
        # pylint: disable=too-many-branches,too-many-locals,too-many-statements
        report = FBReport()
        dmarc_reporter = None
        try:
            dmarc_reporter = dmarcemail.get("from")
            report.reporter = FBReporter.objects.get(email=dmarc_reporter)
        except ObjectDoesNotExist:
            try:
                report.reporter = FBReporter.objects.create(
                    org_name=dmarc_reporter, email=dmarc_reporter,
                )
            except Exception:
                msg = "Failed to find or create reporter {}".format(dmarc_reporter)
                logger.exception(msg)
                raise CommandError(msg)
        except Exception:
            msg = "Unable to get feedback report"
            logger.exception(msg)
            Command.save_email(dmarcemail)
        report.feedback_source = dmarcemail.get_payload()
        out = StringIO()
        gen = Generator(out, maxheaderlen=0)
        gen.flatten(dmarcemail)
        report.email_source = out.getvalue()
        gen = None
        out = None
        logger.info("Feedback report source: %s", report.feedback_source)

        for line in report.feedback_source.splitlines():
            line = line.lstrip()
            (ls0, ls1, ls2) = line.partition(":")
            ls0 = ls0.strip()
            ls2 = ls2.strip()
            if ls1:
                if not report.domain:
                    if ls0 == "Sender Domain":
                        report.domain = ls2
                if not report.source_ip:
                    if ls0 == "Sender IP Address":
                        report.source_ip = ls2
                if not report.date:
                    if ls0 == "Received Date":
                        try:
                            # get tuples
                            tuples = parsedate_tz(ls2)
                            # get timestamp
                            time = mktime_tz(tuples)
                            report.date = datetime.fromtimestamp(time)
                            tz_utc = pytz.timezone("UTC")
                            report.date = report.date.replace(tzinfo=tz_utc)
                        except Exception:
                            msg = "Unable to get date from: {}".format(ls2)
                            logger.exception(msg)
                            report.date = datetime.now()
                if not report.spf_alignment:
                    if ls0 == "SPF Alignment":
                        report.spf_alignment = ls2
                if not report.dkim_alignment:
                    if ls0 == "DKIM Alignment":
                        report.dkim_alignment = ls2
                if not report.dmarc_result:
                    if ls0 == "DMARC Results":
                        report.dmarc_result = ls2
                if not report.email_from:
                    if ls0 == "From":
                        report.email_from = ls2
                if not report.email_subject:
                    if ls0 == "Subject":
                        report.email_subject = ls2
        try:
            report.save()
        except Exception:
            msg = "Failed save from {}".format(dmarc_reporter)
            logger.exception(msg)
            Command.save_email(dmarcemail)
