# -*- coding: utf-8 -*-
import os
import traceback
from email import encoders
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email.mime.image import MIMEImage
from email.mime.multipart import MIMEMultipart
import smtplib

class MailAPI:
    def __init__(self, mail_username, mail_password, mail_port=587, mail_tls=True, mail_relay="smtp.gmail.com"):
        self.MAIL_RELAY = mail_relay
        self.MAIL_PORT = mail_port
        self.MAIL_TLS = mail_tls
        self.MAIL_USERNAME = mail_username
        self.MAIL_PASSWORD = mail_password

    @staticmethod
    def get_inline_image(file_path=None):
        """get_inline_image -- Get image data with Content-ID

        Args:
            file_path (str, optional): Path to inline image. Defaults to None.

        Returns:
            MIMEImage: MIMEImage with Content-ID set to the file path.
        """
        try:
            with open(file_path, 'rb') as f:
                inline_image_data = f.read()
                inline_image = MIMEImage(inline_image_data)
                inline_image.add_header('Content-ID', '<{}>'.format(file_path))
            return inline_image

        except Exception as e:
            print("Exception: {}".format(e))
            return None

    def send_mail(
            self,
            subject,
            text,
            from_email_box,
            to_email_box,
            cc_email_box,
            bcc_email_box,
            inline_files=None,
            attachments=None):
        """
        Generic send email function to email with attachments

        Input: from, to, subject, text, files, server

        Return: Boolean - True if works
        """
        if not self.MAIL_RELAY and not self.MAIL_PORT:
            raise ValueError("Need to define MAIL_RELAY and MAIL_PORT")

        # make sure list values are correct.
        if type(to_email_box) != list or type(cc_email_box) != list or type(bcc_email_box) != list:
            raise ValueError("Please ensure to, cc, and bcc email values are a list")

        # ensure if attachments or inline items are there, they are in a list
        if attachments is not None and type(attachments) != list:
            raise ValueError("Please ensure attachments are in a list")

        if inline_files is not None and type(inline_files) != list:
            raise ValueError("Please ensure inline files are in a list")

        # Check that we're firing off at least the basics
        # Note that an empty recipient list WILL NOT cause an exception with send()
        if not all([subject, text, from_email_box]) or not any([to_email_box, cc_email_box, bcc_email_box]):
            raise ValueError(
                "One or more required fields was empty. "
                + "Subject: "
                + str(subject)
                + ", "
                + "Body: "
                + str(text)
                + ", "
                + "Sender: "
                + str(from_email_box)
                + ", "
                + "Recipient: "
                + str(to_email_box)
            )
        all_recpts = []
        if to_email_box:
            all_recpts.extend(to_email_box)
        if cc_email_box:
            all_recpts.extend(cc_email_box)
        if bcc_email_box:
            all_recpts.extend(bcc_email_box)
        msg = MIMEMultipart()
        msg['From'] = from_email_box
        msg['To'] = ", ".join(to_email_box)
        msg['CC'] = ", ".join(cc_email_box)
        msg['Subject'] = subject
        msgText = MIMEText('{}'.format(text), 'html')
        msg.attach(msgText)
        try:
            if inline_files:
                for f in inline_files:
                    inline_image = self.get_inline_image(f)
                    if isinstance(inline_image, MIMEImage):
                        msg.attach(inline_image)
                    else:
                        raise TypeError(
                            "The inline file isn't a MIMEImage. " + "Inline file in question: " + str(f)
                        )
            if attachments:
                for f in attachments:
                    part = MIMEBase('application', 'octet-stream')
                    with open(f, 'rb') as fn:
                        payf = fn.read()
                    part.set_payload(payf)
                    encoders.encode_base64(part)
                    part.add_header('Content-Disposition', 'attachment; filename="{}"'.format(os.path.basename(f)))
                    msg.attach(part)
        except Exception as e:
            print(e)
            raise Exception("issue add images or attachments")
        try:
            mail_server = smtplib.SMTP(self.MAIL_RELAY, self.MAIL_PORT)
            if self.MAIL_TLS:
                mail_server.starttls()
            if self.MAIL_USERNAME and self.MAIL_PASSWORD:
                mail_server.login(self.MAIL_USERNAME, self.MAIL_PASSWORD)
            mail_server.ehlo()
        except Exception as e:
            print(e)
            raise Exception("email login issues")
        try:
            mail_server.sendmail(from_email_box, all_recpts, msg.as_string())
            mail_server.close()
        except Exception as e:
            print(e)
            raise Exception("email sending issues")
        return True