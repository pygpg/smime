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

"""Python module and tools for constructing and sending pgp/mime email.

Uses ``assuan`` to connect to ``gpgme-tool`` for the cryptography.
"""

import logging

from .crypt import get_client_params
from .pgp import sign, encrypt, sign_and_encrypt, decrypt, verify
from .email import (
    header_from_text,
    guess_encoding,
    EncodedMIMEText,
    strip_bcc,
    append_text,
    attach_root,
    getaddresses,
    email_sources,
    email_targets,
)
from .smtp import get_smtp_params, get_smtp, mail

__author__ = 'Jesse P. Johnson'
__author_email__ = 'jpj6652@gmail.com'
__title__ = 'assuan-smime'
__description__ = 'A Python implementation of the `Assuan protocol.'
__version__ = '0.3'
__license__ = 'GPL-3.0'
__all__ = [
    'sign',
    'encrypt',
    'sign_and_encrypt',
    'decrypt',
    'verify',
    'get_smtp_params',
    'get_smtp',
    'mail',
    'get_client_params',
    'header_from_text',
    'guess_encoding',
    'EncodedMIMEText',
    'strip_bcc',
    'append_text',
    'attach_root',
    'getaddresses',
    'email_sources',
    'email_targets',
]


log = logging.getLogger(__name__)
log.setLevel(logging.ERROR)
log.addHandler(logging.StreamHandler())
