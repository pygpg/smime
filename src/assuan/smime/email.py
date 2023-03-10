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

from __future__ import absolute_import

from email.header import decode_header
from email.mime.text import MIMEText
from email.parser import Parser
from email.utils import getaddresses as _getaddresses
from typing import Dict, Generator, Optional, Tuple

# from email.message import Message
# from email.utils import formataddr


ENCODING = 'utf-8'
# ENCODING = 'iso-8859-1'


def header_from_text(text: str):
    r"""Simple wrapper for instantiating a ``Message`` from text.

    >>> text = '\n'.join(
    ...     ['From: me@big.edu', 'To: you@big.edu', 'Subject: testing']
    ... )
    >>> header = header_from_text(text=text)
    >>> print(header.as_string())  # doctest: +REPORT_UDIFF
    From: me@big.edu
    To: you@big.edu
    Subject: testing
    <BLANKLINE>
    <BLANKLINE>
    """
    text = text.strip()
    parser = Parser()
    return parser.parsestr(text, headersonly=True)


def guess_encoding(text):
    r"""
    >>> guess_encoding('hi there')
    'us-ascii'

    >>> guess_encoding('✉')
    'utf-8'
    """
    for encoding in ['us-ascii', ENCODING, 'utf-8']:
        try:
            text.encode(encoding)
        except UnicodeEncodeError:
            pass
        else:
            return encoding
    raise ValueError(text)


def EncodedMIMEText(body: str, encoding: Optional[str] = None) -> MIMEText:
    """Wrap ``MIMEText`` with ``guess_encoding`` detection.

    >>> message = EncodedMIMEText('Hello')
    >>> print(message.as_string())  # doctest: +REPORT_UDIFF
    Content-Type: text/plain; charset="us-ascii"
    MIME-Version: 1.0
    Content-Transfer-Encoding: 7bit
    Content-Disposition: inline
    <BLANKLINE>
    Hello

    >>> message = EncodedMIMEText('Джон Доу')
    >>> print(message.as_string())  # doctest: +REPORT_UDIFF
    Content-Type: text/plain; charset="utf-8"
    MIME-Version: 1.0
    Content-Transfer-Encoding: base64
    Content-Disposition: inline
    <BLANKLINE>
    0JTQttC+0L0g0JTQvtGD
    <BLANKLINE>
    """
    if encoding is None:
        encoding = guess_encoding(body)
    if encoding == 'us-ascii':
        message = MIMEText(body)
    else:
        # Create the message ('plain' stands for Content-Type: text/plain)
        message = MIMEText(body, 'plain', encoding)
    message.add_header('Content-Disposition', 'inline')
    return message


def strip_bcc(message: MIMEText) -> MIMEText:
    """Remove the Bcc field from a ``Message`` in preparation for mailing

    >>> message = EncodedMIMEText('howdy!')
    >>> message['To'] = 'John Doe <jdoe@a.gov.ru>'
    >>> message['Bcc'] = 'Jack <jack@hill.org>, Jill <jill@hill.org>'
    >>> message = strip_bcc(message)
    >>> print(message.as_string())  # doctest: +REPORT_UDIFF
    Content-Type: text/plain; charset="us-ascii"
    MIME-Version: 1.0
    Content-Transfer-Encoding: 7bit
    Content-Disposition: inline
    To: John Doe <jdoe@a.gov.ru>
    <BLANKLINE>
    howdy!
    """
    del message['bcc']
    del message['resent-bcc']
    return message


def append_text(text_part: MIMEText, new_text: str) -> None:
    r"""Append text to the body of a ``plain/text`` part.

    Updates encoding as necessary.

    >>> message = EncodedMIMEText('Hello')
    >>> append_text(message, ' John Doe')
    >>> print(message.as_string())  # doctest: +REPORT_UDIFF
    Content-Type: text/plain; charset="us-ascii"
    MIME-Version: 1.0
    Content-Disposition: inline
    Content-Transfer-Encoding: 7bit
    <BLANKLINE>
    Hello John Doe

    >>> append_text(message, ', Джон Доу')
    >>> print(message.as_string())  # doctest: +REPORT_UDIFF
    MIME-Version: 1.0
    Content-Disposition: inline
    Content-Type: text/plain; charset="utf-8"
    Content-Transfer-Encoding: base64
    <BLANKLINE>
    SGVsbG8gSm9obiBEb2UsINCU0LbQvtC9INCU0L7Rgw==
    <BLANKLINE>

    >>> append_text(message, ', and Jane Sixpack.')
    >>> print(message.as_string())  # doctest: +REPORT_UDIFF
    MIME-Version: 1.0
    Content-Disposition: inline
    Content-Type: text/plain; charset="utf-8"
    Content-Transfer-Encoding: base64
    <BLANKLINE>
    SGVsbG8gSm9obiBEb2UsINCU0LbQvtC9INCU0L7RgywgYW5kIEphbmUgU2l4cGFjay4=
    <BLANKLINE>
    """
    original_encoding = text_part.get_charset().input_charset
    original_payload = str(
        text_part.get_payload(decode=True), original_encoding
    )
    new_payload = f"{original_payload}{new_text}"
    new_encoding = guess_encoding(new_payload)
    if text_part.get('content-transfer-encoding', None):
        # clear CTE so set_payload will set it properly for the new encoding
        del text_part['content-transfer-encoding']
    text_part.set_payload(new_payload, new_encoding)


def attach_root(header: Dict[str, str], root_part: MIMEText) -> MIMEText:
    r"""Copy headers from ``header`` onto ``root_part``.

    >>> header = header_from_text('From: me@big.edu\n')
    >>> body = EncodedMIMEText('Hello')
    >>> message = attach_root(header, body)
    >>> print(message.as_string())  # doctest: +REPORT_UDIFF
    Content-Type: text/plain; charset="us-ascii"
    MIME-Version: 1.0
    Content-Transfer-Encoding: 7bit
    Content-Disposition: inline
    From: me@big.edu
    <BLANKLINE>
    Hello
    """
    for key, value in header.items():
        root_part[key] = value
    return root_part


def getaddresses(addresses) -> Generator[Tuple[str, ...], None, None]:
    """A decoding version of ``email.utils.getaddresses``.

    >>> text = (
    ...     'To: =?utf-8?b?0JTQttC+0L0g0JTQvtGD?= <jdoe@a.gov.ru>, '
    ...     'Jack <jack@hill.org>'
    ... )
    >>> header = header_from_text(text=text)
    >>> list(getaddresses(header.get_all('to', [])))
    [('Джон Доу', 'jdoe@a.gov.ru'), ('Jack', 'jack@hill.org')]
    """
    for (name, address) in _getaddresses(addresses):
        n = []
        for b, encoding in decode_header(name):
            if encoding is None:
                n.append(b)
            else:
                n.append(str(b, encoding))
        yield (' '.join(n), address)


def email_sources(message):
    """Extract author address from an email ``Message``

    Search the header of an email Message instance to find the
    senders' email addresses (or sender's address).

    >>> text = (
    ...     'From: =?utf-8?b?0JTQttC+0L0g0JTQvtGD?= <jdoe@a.gov.ru>, '
    ...     'Jack <jack@hill.org>'
    ... )
    >>> header = header_from_text(text=text)
    >>> list(email_sources(header))
    [('Джон Доу', 'jdoe@a.gov.ru'), ('Jack', 'jack@hill.org')]
    """
    froms = message.get_all('from', [])
    return getaddresses(froms)  # [(name, address), ...]


def email_targets(message):
    """Extract recipient addresses from an email ``Message``

    Search the header of an email Message instance to find a
    list of recipient's email addresses.

    >>> text = (
    ...     'To: =?utf-8?b?0JTQttC+0L0g0JTQvtGD?= <jdoe@a.gov.ru>, '
    ...     'Jack <jack@hill.org>'
    ... )
    >>> header = header_from_text(text=text)
    >>> list(email_targets(header))
    [('Джон Доу', 'jdoe@a.gov.ru'), ('Jack', 'jack@hill.org')]
    """
    tos = message.get_all('to', [])
    ccs = message.get_all('cc', [])
    bccs = message.get_all('bcc', [])
    resent_tos = message.get_all('resent-to', [])
    resent_ccs = message.get_all('resent-cc', [])
    resent_bccs = message.get_all('resent-bcc', [])
    return getaddresses(
        tos + ccs + bccs + resent_tos + resent_ccs + resent_bccs
    )
