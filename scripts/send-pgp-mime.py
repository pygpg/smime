#!/usr/bin/env python3.3
# Copyright (C) 2022 Jesse P. Johnson <jpj6652@gmail.com>
# Copyright (C) 2012 W. Trevor King <wking@tremily.us>
#
# This file is part of assuan-smime.
#
# assuan-smime is free software: you can redistribute it and/or modify it under the
# terms of the GNU General Public License as published by the Free Software
# Foundation, either version 3 of the License, or (at your option) any later
# version.
#
# assuan-smime is distributed in the hope that it will be useful, but WITHOUT ANY
# WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
# A PARTICULAR PURPOSE.  See the GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along with
# assuan-smime.  If not, see <http://www.gnu.org/licenses/>.

"""Scriptable PGP MIME email using ``gpg``.

You can use ``gpg-agent`` for passphrase caching if your key requires
a passphrase (it better!).  Example usage would be to install
``gpg-agent``, and then run::

  $ export GPG_TTY=`tty`
  $ eval $(gpg-agent --daemon)

in your shell before invoking this script.  See ``gpg-agent(1)`` for
more details.
"""

import codecs
import logging
import mimetypes
import os
import sys
from configparser import ConfigParser
from email.encoders import encode_base64
from email.mime.application import MIMEApplication
from email.mime.audio import MIMEAudio
from email.mime.image import MIMEImage
from email.mime.multipart import MIMEMultipart
from email.mime.nonmultipart import MIMENonMultipart
from typing import Optional

from assuan import smime

log = logging.getLogger(__name__)

STDIN_USED = False


def read_file(filename: Optional[str] = None, encoding: str = 'us-ascii'):
    global STDIN_USED
    if filename == '-':
        assert STDIN_USED is False, STDIN_USED
        STDIN_USED = True
        return sys.stdin.read()
    if filename:
        return codecs.open(filename, 'r', encoding).read()
    raise ValueError('neither filename nor descriptor given for reading')


def load_attachment(filename: str, encoding: str = 'us-ascii'):
    mimetype, content_encoding = mimetypes.guess_type(filename)
    if mimetype is None or content_encoding is not None:
        mimetype = 'application/octet-stream'
    maintype, subtype = mimetype.split('/', 1)
    log.info(
        'loading attachment %s as %s (%s)',
        filename,
        mimetype,
        content_encoding,
    )
    if maintype == 'text':
        text = read_file(filename=filename, encoding=encoding)
        attachment = smime.EncodedMIMEText(text)
        del attachment['content-disposition']
    else:
        data = open(filename, 'rb').read()
        if maintype == 'application':
            attachment = MIMEApplication(data, subtype)
        elif maintype == 'audio':
            attachment = MIMEAudio(data)
        elif maintype == 'image':
            attachment = MIMEImage(data)
        else:
            attachment = MIMENonMultipart(maintype, subtype)
            attachment.set_payload(data, encode_base64)
    attachment.add_header(
        'Content-Disposition', 'attachment', filename=filename
    )
    return attachment


if __name__ == '__main__':
    import argparse

    doc_lines = __doc__.splitlines()
    parser = argparse.ArgumentParser(
        description=doc_lines[0],
        epilog='\n'.join(doc_lines[1:]).strip(),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        '-v',
        '--version',
        action='version',
        version='%(prog)s {}'.format(smime.__version__),
    )
    parser.add_argument(
        '-e',
        '--encoding',
        metavar='ENCODING',
        default='utf-8',
        help='encoding for input files',
    )
    parser.add_argument(
        '-H',
        '--header-file',
        metavar='FILE',
        help='file containing email header',
    )
    parser.add_argument(
        '-B', '--body-file', metavar='FILE', help='file containing email body'
    )
    parser.add_argument(
        '-a',
        '--attachment',
        metavar='FILE',
        action='append',
        help='add an attachment to your message',
    )
    parser.add_argument(
        '-m',
        '--mode',
        default='sign',
        metavar='MODE',
        choices=['sign', 'encrypt', 'sign-encrypt', 'plain'],
        help='encryption mode',
    )
    parser.add_argument(
        '-s',
        '--sign-as',
        metavar='KEY',
        help="gpg key to sign with (gpg's -u/--local-user)",
    )
    parser.add_argument(
        '-c',
        '--config',
        metavar='FILE',
        default=os.path.expanduser(
            os.path.join('~', '.config', 'smtplib.conf')
        ),
        help='SMTP config file for sending mail',
    ),
    parser.add_argument(
        '--output',
        action='store_const',
        const=True,
        help="don't mail the generated message, print it to stdout instead",
    )
    parser.add_argument(
        '-V',
        '--verbose',
        default=0,
        action='count',
        help='increment verbosity',
    )

    args = parser.parse_args()

    if args.verbose:
        log.setLevel(max(logging.DEBUG, log.level - 10 * args.verbose))

    header_text = read_file(filename=args.header_file, encoding=args.encoding)
    header = smime.header_from_text(header_text)
    body_text = read_file(filename=args.body_file, encoding=args.encoding)
    body = smime.encodedMIMEText(body_text)
    if args.attachment:
        b = MIMEMultipart()
        b.attach(body)
        body = b
        mimetypes.init()
        for attachment in args.attachment:
            body.attach(
                load_attachment(filename=attachment, encoding=args.encoding)
            )

    config = ConfigParser()
    config.read(args.config)
    client_params = smime.get_client_params(config)

    if args.sign_as:
        signers = [args.sign_as]
    else:
        signers = None
    if 'encrypt' in args.mode:
        recipients = [email for name, email in smime.email_targets(header)]
    if args.mode == 'sign':
        body = smime.sign(
            body, signers=signers, allow_default_signer=True, **client_params
        )
    elif args.mode == 'encrypt':
        body = smime.encrypt(body, recipients=recipients, **client_params)
    elif args.mode == 'sign-encrypt':
        body = smime.sign_and_encrypt(
            body,
            signers=signers,
            recipients=recipients,
            allow_default_signer=True,
            **client_params
        )
    elif args.mode == 'plain':
        pass
    else:
        raise Exception('unrecognized mode {}'.format(args.mode))
    message = smime.attach_root(header, body)

    if args.output:
        print(message.as_string())
    else:
        smtp_params = smime.get_smtp_params(config)
        smtp = smime.get_smtp(*smtp_params)
        try:
            smime.mail(message, smtp)
        finally:
            log.info('disconnect from SMTP server')
            smtp.quit()
