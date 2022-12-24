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

"""Provide SMTP capability."""

import logging
from smtplib import SMTP, SMTP_PORT
from configparser import NoSectionError, NoOptionError
from typing import TYPE_CHECKING, Optional, Tuple

if TYPE_CHECKING:
    from configparser import ConfigParser
    from mail.mime.text import MIMEText  # type: ignore

log = logging.getLogger(__name__)


def get_smtp_params(
    config: 'ConfigParser',
) -> Tuple[
    Optional[str], Optional[int], Optional[bool], Optional[str], Optional[str]
]:
    r"""Retrieve SMTP paramters from a config file.

    >>> from configparser import ConfigParser
    >>> config = ConfigParser()
    >>> config.read_string(
    ...     '\n'.join(
    ...         [
    ...             '[smtp]',
    ...             'host: smtp.mail.uu.edu',
    ...             'port: 587',
    ...             'starttls: yes',
    ...             'username: rincewind',
    ...             'password: 7ugg@g3',
    ...         ]
    ...     )
    ... )
    >>> get_smtp_params(config)
    ('smtp.mail.uu.edu', 587, True, 'rincewind', '7ugg@g3')

    >>> config = ConfigParser()
    >>> get_smtp_params(ConfigParser())
    (None, None, None, None, None)
    """
    try:
        host = config.get('smtp', 'host')
    except NoSectionError:
        return (None, None, None, None, None)
    except NoOptionError:
        host = None

    try:
        port = config.getint('smtp', 'port')
    except NoOptionError:
        port = None

    try:
        starttls = config.getboolean('smtp', 'starttls')
    except NoOptionError:
        starttls = None

    try:
        username = config.get('smtp', 'username')
    except NoOptionError:
        username = None

    try:
        password = config.get('smtp', 'password')
    except NoOptionError:
        password = None
    return (host, port, starttls, username, password)


def get_smtp(
    host: Optional[str] = None,
    port: Optional[int] = None,
    starttls: Optional[bool] = None,
    username: Optional[str] = None,
    password: Optional[str] = None,
) -> SMTP:
    """Connect to an SMTP host using the given parameters.

    >>> from smtplib import SMTPAuthenticationError
    >>> try:  # doctest: +SKIP
    ...     smtp = get_smtp(
    ...         host='smtp.gmail.com',
    ...         port=587,
    ...         starttls=True,
    ...         username='rincewind@uu.edu',
    ...         password='7ugg@g3',
    ...     )
    ... except SMTPAuthenticationError:
    ...     print('that was not a real account')
    that was not a real account

    >>> smtp = get_smtp()  # doctest: +SKIP
    >>> smtp.quit()  # doctest: +SKIP
    """
    if host is None:
        host = 'localhost'
    if port is None:
        port = SMTP_PORT
    if username and not starttls:
        raise ValueError(
            'sending passwords in the clear is unsafe! Use STARTTLS.'
        )
    log.info('connect to SMTP server at %s:%d', host, port)
    smtp = SMTP(host=host, port=port)
    smtp.ehlo()
    if starttls:
        smtp.starttls()
    if username and password:
        smtp.login(username, password)
    # smtp.set_debuglevel(1)
    return smtp


def mail(
    message: 'MIMEText',
    smtp: Optional['SMTP'] = None,
    # sendmail: Optional[str] = None,
) -> None:
    """Send an email ``Message`` instance on its merry way.

    We can shell out to the user specified sendmail in case
    the local host doesn't have an SMTP server set up
    for easy ``smtplib`` usage.

    >>> from assuan.smime.email import EncodedMIMEText
    >>> message = EncodedMIMEText('howdy!')
    >>> message['From'] = 'John Doe <jdoe@a.gov.ru>'
    >>> message['To'] = 'Jack <jack@hill.org>, Jill <jill@hill.org>'
    >>> SENDMAIL = ['/usr/sbin/sendmail', '-t']
    >>> mail(message=message, sendmail=SENDMAIL)  # doctest: +SKIP
    """
    log.info('send message %s -> %s', message['from'], message['to'])
    if smtp:
        smtp.send_message(msg=message)
    # elif sendmail:
    #     execute(
    #         sendmail,
    #         stdin=message.as_string().encode('us-ascii'),
    #         close_fds=True,
    #     )
    else:
        smtp = SMTP()
        smtp.connect()
        smtp.send_message(msg=message)
        smtp.close()
