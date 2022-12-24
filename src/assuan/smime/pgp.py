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

"""PGP capabilities for S/MIME."""

import logging
from copy import deepcopy
from email import message_from_bytes
from email.encoders import encode_7or8bit
from email.generator import BytesGenerator
from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email import policy as _email_policy
from io import BytesIO
from typing import Any, List, Optional

from .crypt import sign_and_encrypt_bytes
from .crypt import verify_bytes
from .email import email_targets
from .email import strip_bcc

log = logging.getLogger(__name__)


def _flatten(message):
    r"""Flatten a message to bytes.

    >>> from assuan.smime.email import EncodedMIMEText
    >>> message = EncodedMIMEText('Hi\nBye')
    >>> _flatten(message)  # doctest: +ELLIPSIS
    b'Content-Type: text/plain; charset="us-ascii"\r\nMIME-Version: ...'
    """
    bytesio = BytesIO()
    generator = BytesGenerator(bytesio, policy=_email_policy.SMTP)
    generator.flatten(message)
    return bytesio.getvalue()


def sign(message: str, **kwargs: Any) -> MIMEMultipart:
    r"""Sign a ``Message``, returning the signed version.

    multipart/signed
    +-> text/plain                 (body)
    +-> application/pgp-signature  (signature)

    >>> from assuan.smime.email import EncodedMIMEText
    >>> message = EncodedMIMEText('Hi\nBye')
    >>> signed = sign(message, signers=['assuan-smime@invalid.com'])
    >>> signed.set_boundary('boundsep')
    >>> print(
    ...     signed.as_string().replace(
    ...         'micalg="pgp-sha1"; protocol="application/pgp-signature"',
    ...         'protocol="application/pgp-signature"; micalg="pgp-sha1"',
    ...     )
    ... )
    ... # doctest: +ELLIPSIS, +REPORT_UDIFF
    Content-Type: multipart/signed; protocol="application/pgp-signature"; micalg="pgp-sha1"; boundary="boundsep"
    MIME-Version: 1.0
    Content-Disposition: inline
    <BLANKLINE>
    --boundsep
    Content-Type: text/plain; charset="us-ascii"
    MIME-Version: 1.0
    Content-Transfer-Encoding: 7bit
    Content-Disposition: inline
    <BLANKLINE>
    Hi
    Bye
    --boundsep
    MIME-Version: 1.0
    Content-Transfer-Encoding: 7bit
    Content-Description: OpenPGP digital signature
    Content-Type: application/pgp-signature; name="signature.asc"; charset="us-ascii"
    <BLANKLINE>
    -----BEGIN PGP SIGNATURE-----
    Version: GnuPG...
    -----END PGP SIGNATURE-----
    <BLANKLINE>
    --boundsep--

    >>> from email.mime.multipart import MIMEMultipart
    >>> message = MIMEMultipart()
    >>> message.attach(EncodedMIMEText('Part A'))
    >>> message.attach(EncodedMIMEText('Part B'))
    >>> signed = sign(message, signers=['assuan-smime@invalid.com'])
    >>> signed.set_boundary('boundsep')
    >>> print(
    ...     signed.as_string().replace(
    ...         'micalg="pgp-sha1"; protocol="application/pgp-signature"',
    ...         'protocol="application/pgp-signature"; micalg="pgp-sha1"',
    ...     )
    ... )
    ... # doctest: +ELLIPSIS, +REPORT_UDIFF
    Content-Type: multipart/signed; protocol="application/pgp-signature"; micalg="pgp-sha1"; boundary="boundsep"
    MIME-Version: 1.0
    Content-Disposition: inline
    <BLANKLINE>
    --boundsep
    Content-Type: multipart/mixed; boundary="===============...=="
    MIME-Version: 1.0
    <BLANKLINE>
    --===============...==
    Content-Type: text/plain; charset="us-ascii"
    MIME-Version: 1.0
    Content-Transfer-Encoding: 7bit
    Content-Disposition: inline
    <BLANKLINE>
    Part A
    --===============...==
    Content-Type: text/plain; charset="us-ascii"
    MIME-Version: 1.0
    Content-Transfer-Encoding: 7bit
    Content-Disposition: inline
    <BLANKLINE>
    Part B
    --===============...==--
    --boundsep
    MIME-Version: 1.0
    Content-Transfer-Encoding: 7bit
    Content-Description: OpenPGP digital signature
    Content-Type: application/pgp-signature; name="signature.asc"; charset="us-ascii"
    <BLANKLINE>
    -----BEGIN PGP SIGNATURE-----
    Version: GnuPG...
    -----END PGP SIGNATURE-----
    <BLANKLINE>
    --boundsep--
    """
    body = _flatten(message)
    signature = str(sign_and_encrypt_bytes(data=body, **kwargs), 'us-ascii')
    sig = MIMEApplication(
        _data=signature,
        _subtype='pgp-signature; name="signature.asc"',
        _encoder=encode_7or8bit,
    )
    sig['Content-Description'] = 'OpenPGP digital signature'
    sig.set_charset('us-ascii')

    msg = MIMEMultipart(
        'signed', micalg='pgp-sha1', protocol='application/pgp-signature'
    )
    msg.attach(message)
    msg.attach(sig)
    msg['Content-Disposition'] = 'inline'
    return msg


def encrypt(message, recipients=None, **kwargs):
    r"""Encrypt a ``Message``, returning the encrypted version.

    multipart/encrypted
    +-> application/pgp-encrypted  (control information)
    +-> application/octet-stream   (body)

    >>> from assuan.smime.email import EncodedMIMEText
    >>> message = EncodedMIMEText('Hi\nBye')
    >>> message['To'] = 'assuan-smime-test <assuan-smime@invalid.com>'
    >>> encrypted = encrypt(message, always_trust=True)
    >>> encrypted.set_boundary('boundsep')
    >>> print(
    ...     encrypted.as_string().replace(
    ...         'micalg="pgp-sha1"; protocol="application/pgp-encrypted"',
    ...         'protocol="application/pgp-encrypted"; micalg="pgp-sha1"',
    ...     )
    ... )
    ... # doctest: +ELLIPSIS, +REPORT_UDIFF
    Content-Type: multipart/encrypted; protocol="application/pgp-encrypted"; micalg="pgp-sha1"; boundary="boundsep"
    MIME-Version: 1.0
    Content-Disposition: inline
    <BLANKLINE>
    --boundsep
    MIME-Version: 1.0
    Content-Transfer-Encoding: 7bit
    Content-Type: application/pgp-encrypted; charset="us-ascii"
    <BLANKLINE>
    Version: 1
    <BLANKLINE>
    --boundsep
    MIME-Version: 1.0
    Content-Transfer-Encoding: 7bit
    Content-Description: OpenPGP encrypted message
    Content-Type: application/octet-stream; name="encrypted.asc"; charset="us-ascii"
    <BLANKLINE>
    -----BEGIN PGP MESSAGE-----
    Version: GnuPG...
    -----END PGP MESSAGE-----
    <BLANKLINE>
    --boundsep--

    >>> from email.mime.multipart import MIMEMultipart
    >>> message = MIMEMultipart()
    >>> message.attach(EncodedMIMEText('Part A'))
    >>> message.attach(EncodedMIMEText('Part B'))
    >>> encrypted = encrypt(
    ...     message, recipients=['assuan-smime@invalid.com'], always_trust=True
    ... )
    >>> encrypted.set_boundary('boundsep')
    >>> print(
    ...     encrypted.as_string().replace(
    ...         'micalg="pgp-sha1"; protocol="application/pgp-encrypted"',
    ...         'protocol="application/pgp-encrypted"; micalg="pgp-sha1"',
    ...     )
    ... )
    ... # doctest: +ELLIPSIS, +REPORT_UDIFF
    Content-Type: multipart/encrypted; protocol="application/pgp-encrypted"; micalg="pgp-sha1"; boundary="boundsep"
    MIME-Version: 1.0
    Content-Disposition: inline
    <BLANKLINE>
    --boundsep
    MIME-Version: 1.0
    Content-Transfer-Encoding: 7bit
    Content-Type: application/pgp-encrypted; charset="us-ascii"
    <BLANKLINE>
    Version: 1
    <BLANKLINE>
    --boundsep
    MIME-Version: 1.0
    Content-Transfer-Encoding: 7bit
    Content-Description: OpenPGP encrypted message
    Content-Type: application/octet-stream; name="encrypted.asc"; charset="us-ascii"
    <BLANKLINE>
    -----BEGIN PGP MESSAGE-----
    Version: GnuPG...
    -----END PGP MESSAGE-----
    <BLANKLINE>
    --boundsep--
    """
    body = _flatten(message)
    if recipients is None:
        recipients = [email for name, email in email_targets(message)]
        log.debug('extracted encryption recipients: %s', recipients)
    encrypted = str(
        sign_and_encrypt_bytes(data=body, recipients=recipients, **kwargs),
        'us-ascii',
    )
    enc = MIMEApplication(
        _data=encrypted,
        _subtype='octet-stream; name="encrypted.asc"',
        _encoder=encode_7or8bit,
    )
    enc['Content-Description'] = 'OpenPGP encrypted message'
    enc.set_charset('us-ascii')
    control = MIMEApplication(
        _data='Version: 1\n',
        _subtype='pgp-encrypted',
        _encoder=encode_7or8bit,
    )
    control.set_charset('us-ascii')
    msg = MIMEMultipart(
        'encrypted', micalg='pgp-sha1', protocol='application/pgp-encrypted'
    )
    msg.attach(control)
    msg.attach(enc)
    msg['Content-Disposition'] = 'inline'
    return msg


def sign_and_encrypt(
    message,
    signers: Optional[List[str]] = None,
    recipients: Optional[List[str]] = None,
    **kwargs: Any,
):
    r"""Sign and encrypt a ``Message``, returning the encrypted version.

    multipart/encrypted
     +-> application/pgp-encrypted  (control information)
     +-> application/octet-stream   (body)

    >>> from assuan.smime.email import EncodedMIMEText
    >>> message = EncodedMIMEText('Hi\nBye')
    >>> message['To'] = 'assuan-smime-test <assuan-smime@invalid.com>'
    >>> encrypted = sign_and_encrypt(
    ...     message, signers=['assuan-smime@invalid.com'], always_trust=True
    ... )
    >>> encrypted.set_boundary('boundsep')
    >>> print(
    ...     encrypted.as_string().replace(
    ...         'micalg="pgp-sha1"; protocol="application/pgp-encrypted"',
    ...         'protocol="application/pgp-encrypted"; micalg="pgp-sha1"',
    ...     )
    ... )
    ... # doctest: +ELLIPSIS, +REPORT_UDIFF
    Content-Type: multipart/encrypted; protocol="application/pgp-encrypted"; micalg="pgp-sha1"; boundary="boundsep"
    MIME-Version: 1.0
    Content-Disposition: inline
    <BLANKLINE>
    --boundsep
    MIME-Version: 1.0
    Content-Transfer-Encoding: 7bit
    Content-Type: application/pgp-encrypted; charset="us-ascii"
    <BLANKLINE>
    Version: 1
    <BLANKLINE>
    --boundsep
    MIME-Version: 1.0
    Content-Transfer-Encoding: 7bit
    Content-Description: OpenPGP encrypted message
    Content-Type: application/octet-stream; name="encrypted.asc"; charset="us-ascii"
    <BLANKLINE>
    -----BEGIN PGP MESSAGE-----
    Version: GnuPG...
    -----END PGP MESSAGE-----
    <BLANKLINE>
    --boundsep--

    >>> from email.mime.multipart import MIMEMultipart
    >>> message = MIMEMultipart()
    >>> message.attach(EncodedMIMEText('Part A'))
    >>> message.attach(EncodedMIMEText('Part B'))
    >>> encrypted = sign_and_encrypt(
    ...     message,
    ...     signers=['assuan-smime@invalid.com'],
    ...     recipients=['assuan-smime@invalid.com'],
    ...     always_trust=True,
    ... )
    >>> encrypted.set_boundary('boundsep')
    >>> print(
    ...     encrypted.as_string().replace(
    ...         'micalg="pgp-sha1"; protocol="application/pgp-encrypted"',
    ...         'protocol="application/pgp-encrypted"; micalg="pgp-sha1"',
    ...     )
    ... )
    ... # doctest: +ELLIPSIS, +REPORT_UDIFF
    Content-Type: multipart/encrypted; protocol="application/pgp-encrypted"; micalg="pgp-sha1"; boundary="boundsep"
    MIME-Version: 1.0
    Content-Disposition: inline
    <BLANKLINE>
    --boundsep
    MIME-Version: 1.0
    Content-Transfer-Encoding: 7bit
    Content-Type: application/pgp-encrypted; charset="us-ascii"
    <BLANKLINE>
    Version: 1
    <BLANKLINE>
    --boundsep
    MIME-Version: 1.0
    Content-Transfer-Encoding: 7bit
    Content-Description: OpenPGP encrypted message
    Content-Type: application/octet-stream; name="encrypted.asc"; charset="us-ascii"
    <BLANKLINE>
    -----BEGIN PGP MESSAGE-----
    Version: GnuPG...
    -----END PGP MESSAGE-----
    <BLANKLINE>
    --boundsep--
    """
    strip_bcc(message=message)
    body = _flatten(message)
    if recipients is None:
        recipients = [email for name, email in email_targets(message)]
        log.debug('extracted encryption recipients: %s', recipients)
    encrypted = str(
        sign_and_encrypt_bytes(
            data=body, signers=signers, recipients=recipients, **kwargs
        ),
        'us-ascii',
    )
    enc = MIMEApplication(
        _data=encrypted,
        _subtype='octet-stream; name="encrypted.asc"',
        _encoder=encode_7or8bit,
    )
    enc['Content-Description'] = 'OpenPGP encrypted message'
    enc.set_charset('us-ascii')
    control = MIMEApplication(
        _data='Version: 1\n',
        _subtype='pgp-encrypted',
        _encoder=encode_7or8bit,
    )
    control.set_charset('us-ascii')
    msg = MIMEMultipart(
        'encrypted', micalg='pgp-sha1', protocol='application/pgp-encrypted'
    )
    msg.attach(control)
    msg.attach(enc)
    msg['Content-Disposition'] = 'inline'
    return msg


def _get_encrypted_parts(message):
    content_type = message.get_content_type()
    assert content_type == 'multipart/encrypted', content_type
    params = dict(message.get_params())
    assert params.get('protocol', None) == 'application/pgp-encrypted', params
    assert message.is_multipart(), message
    control = body = None
    for part in message.get_payload():
        if part == message:
            continue
        assert part.is_multipart() is False, part
        content_type = part.get_content_type()
        if content_type == 'application/pgp-encrypted':
            if control:
                raise ValueError('multiple application/pgp-encrypted parts')
            control = part
        elif content_type == 'application/octet-stream':
            if body:
                raise ValueError('multiple application/octet-stream parts')
            body = part
        else:
            raise ValueError(f"unnecessary {content_type} part")
    if not control:
        raise ValueError('missing application/pgp-encrypted part')
    if not body:
        raise ValueError('missing application/octet-stream part')
    return (control, body)


def _get_signed_parts(message):
    content_type = message.get_content_type()
    assert content_type == 'multipart/signed', content_type
    params = dict(message.get_params())
    assert params.get('protocol', None) == 'application/pgp-signature', params
    assert message.is_multipart(), message
    body = signature = None
    for part in message.get_payload():
        if part == message:
            continue
        content_type = part.get_content_type()
        if content_type == 'application/pgp-signature':
            if signature:
                raise ValueError('multiple application/pgp-signature parts')
            signature = part
        else:
            if body:
                raise ValueError('multiple non-signature parts')
            body = part
    if not body:
        raise ValueError('missing body part')
    if not signature:
        raise ValueError('missing application/pgp-signature part')
    return (body, signature)


def decrypt(message, **kwargs):
    r"""Decrypt a multipart/encrypted message.

    >>> from assuan.smime.email import EncodedMIMEText
    >>> message = EncodedMIMEText('Hi\nBye')
    >>> encrypted = encrypt(
    ...     message,
    ...     recipients=['<assuan-smime@invalid.com>'],
    ...     always_trust=True,
    ... )
    >>> decrypted = decrypt(encrypted)
    >>> print(decrypted.as_string().replace('\r\n', '\n'))
    ... # doctest: +ELLIPSIS, +REPORT_UDIFF
    Content-Type: text/plain; charset="us-ascii"
    MIME-Version: 1.0
    Content-Transfer-Encoding: 7bit
    Content-Disposition: inline
    <BLANKLINE>
    Hi
    Bye

    >>> from email.mime.multipart import MIMEMultipart
    >>> message = MIMEMultipart()
    >>> message.attach(EncodedMIMEText('Part A'))
    >>> message.attach(EncodedMIMEText('Part B'))
    >>> encrypted = encrypt(
    ...     message, recipients=['assuan-smime@invalid.com'], always_trust=True
    ... )
    >>> decrypted = decrypt(encrypted)
    >>> decrypted.set_boundary('boundsep')
    >>> print(decrypted.as_string())  # doctest: +ELLIPSIS, +REPORT_UDIFF
    Content-Type: multipart/mixed; boundary="boundsep"
    MIME-Version: 1.0
    <BLANKLINE>
    --boundsep
    Content-Type: text/plain; charset="us-ascii"
    MIME-Version: 1.0
    Content-Transfer-Encoding: 7bit
    Content-Disposition: inline
    <BLANKLINE>
    Part A
    --boundsep
    Content-Type: text/plain; charset="us-ascii"
    MIME-Version: 1.0
    Content-Transfer-Encoding: 7bit
    Content-Disposition: inline
    <BLANKLINE>
    Part B
    --boundsep--
    <BLANKLINE>
    """
    _, body = _get_encrypted_parts(message)  # control
    encrypted = body.get_payload(decode=True)
    if not isinstance(encrypted, bytes):
        encrypted = encrypted.encode('us-ascii')
    decrypted, _, _ = verify_bytes(encrypted, **kwargs)  # verified, result
    return message_from_bytes(decrypted)


def verify(message, **kwargs):
    r"""Verify a signature on ``message``, possibly decrypting first.

    >>> from assuan.smime.email import EncodedMIMEText
    >>> message = EncodedMIMEText('Hi\nBye')
    >>> message['To'] = 'assuan-smime-test <assuan-smime@invalid.com>'
    >>> encrypted = sign_and_encrypt(
    ...     message,
    ...     signers=['assuan-smime@invalid.com'],
    ...     always_trust=True,
    ... )
    >>> decrypted,verified,signatures = verify(encrypted)
    >>> print(decrypted.as_string().replace('\r\n', '\n'))
    ... # doctest: +ELLIPSIS, +REPORT_UDIFF
    Content-Type: text/plain; charset="us-ascii"
    MIME-Version: 1.0
    Content-Transfer-Encoding: 7bit
    Content-Disposition: inline
    To: assuan-smime-test <assuan-smime@invalid.com>
    <BLANKLINE>
    Hi
    Bye

    >>> verified
    False

    >>> for s in signatures:
    ...     print(s.dumps())  # doctest: +REPORT_UDIFF
    ... # doctest: +REPORT_UDIFF, +ELLIPSIS
    DECC812C8795ADD60538B0CD171008BA2F73DE2E signature:
      summary:
        CRL missing: False
        CRL too old: False
        bad policy: False
        green: False
        key expired: False
        key missing: False
        key revoked: False
        red: False
        signature expired: False
        system error: False
        valid: False
      status: success
      timestamp: ...
      expiration timestamp: None
      wrong key usage: False
      pka trust: not available
      chain model: False
      validity: unknown
      validity reason: success
      public key algorithm: RSA
      hash algorithm: SHA256

    >>> from email.mime.multipart import MIMEMultipart
    >>> message = MIMEMultipart()
    >>> message.attach(EncodedMIMEText('Part A'))
    >>> message.attach(EncodedMIMEText('Part B'))
    >>> signed = sign(message, signers=['assuan-smime@invalid.com'])
    >>> decrypted,verified,signatures = verify(signed)
    >>> decrypted.set_boundary('boundsep')
    >>> print(decrypted.as_string())  # doctest: +ELLIPSIS, +REPORT_UDIFF
    Content-Type: multipart/mixed; boundary="boundsep"
    MIME-Version: 1.0
    <BLANKLINE>
    --boundsep
    Content-Type: text/plain; charset="us-ascii"
    MIME-Version: 1.0
    Content-Transfer-Encoding: 7bit
    Content-Disposition: inline
    <BLANKLINE>
    Part A
    --boundsep
    Content-Type: text/plain; charset="us-ascii"
    MIME-Version: 1.0
    Content-Transfer-Encoding: 7bit
    Content-Disposition: inline
    <BLANKLINE>
    Part B
    --boundsep--

    >>> verified
    False

    >>> for s in signatures:
    ...     print(s.dumps())  # doctest: +REPORT_UDIFF
    ... # doctest: +REPORT_UDIFF, +ELLIPSIS
    DECC812C8795ADD60538B0CD171008BA2F73DE2E signature:
      summary:
        CRL missing: False
        CRL too old: False
        bad policy: False
        green: False
        key expired: False
        key missing: False
        key revoked: False
        red: False
        signature expired: False
        system error: False
        valid: False
      status: success
      timestamp: ...
      expiration timestamp: None
      wrong key usage: False
      pka trust: not available
      chain model: False
      validity: unknown
      validity reason: success
      public key algorithm: RSA
      hash algorithm: SHA1

    Test a message generated by Mutt (for sanity):

    >>> from email import message_from_bytes
    >>> message_bytes = b'\n'.join([
    ...   b'Return-Path: <assuan-smime@invalid.com>',
    ...   b'Received: by invalid; Tue, 24 Apr 2012 19:46:59 -0400',
    ...   b'Date: Tue, 24 Apr 2012 19:46:59 -0400',
    ...   b'From: assuan-smime-test <assuan-smime@invalid.com',
    ...   b'To: assuan-smime@invalid.com',
    ...   b'Subject: test',
    ...   b'Message-ID: <20120424233415.GA27788@invalid>',
    ...   b'MIME-Version: 1.0',
    ...   b'Content-Type: multipart/signed; micalg=pgp-sha1;',
    ...   b'  protocol="application/pgp-signature";',
    ...   b'  boundary="kORqDWCi7qDJ0mEj"',
    ...   b'Content-Disposition: inline',
    ...   b'User-Agent: Mutt/1.5.21 (2010-09-15)',
    ...   b'Content-Length: 740',
    ...   b'',
    ...   b'',
    ...   b'--kORqDWCi7qDJ0mEj',
    ...   b'Content-Type: text/plain; charset=us-ascii',
    ...   b'Content-Disposition: inline',
    ...   b'',
    ...   b'ping!',
    ...   b'',
    ...   b'--kORqDWCi7qDJ0mEj',
    ...   b'Content-Type: application/pgp-signature; name="signature.asc"',
    ...   b'Content-Description: OpenPGP digital signature',
    ...   b'',
    ...   b'-----BEGIN PGP SIGNATURE-----',
    ...   b'Version: GnuPG v2.0.17 (GNU/Linux)',
    ...   b'',
    ...   b'iQEcBAEBAgAGBQJPlztxAAoJEFEa7aZDMrbjwT0H/i9eN6CJ2FIinK7Ps04XYEbL',
    ...   b'PSQV1xCxb+2bk7yA4zQnjAKOPSuMDXfVG669Pbj8yo4DOgUqIgh+lK+voec9uwsJ',
    ...   b'ZgUJcMozSmEFSTPO+Fiyx0S+NjnaLsas6IQrQTVDc6lWiIZttgxuN0crH5DcLomB',
    ...   b'Ip90+ELbzVN3yBAjMJ1Y6xnKd7C0IOKm7VunYu9eCzJ/Rik5qZ0+IacQQnnrFJEN',
    ...   b'04nDvDUzfaKy80Ke7VAQBIRi85XCsM2h0KDXOGUZ0xPQ8L/4eUK9tL6DJaqKqFPl',
    ...   b'zNiwfpue01o6l6kngrQdXZ3tuv0HbLGc4ACzfz5XuGvE5PYTNEsylKLUMiSCIFc=',
    ...   b'=xP0S',
    ...   b'-----END PGP SIGNATURE-----',
    ...   b'',
    ...   b'--kORqDWCi7qDJ0mEj--',
    ...   b'',
    ... ])
    >>> message = message_from_bytes(message_bytes)
    >>> decrypted,verified,signatures = verify(message)
    >>> print(decrypted.as_string())  # doctest: +ELLIPSIS, +REPORT_UDIFF
    Content-Type: text/plain; charset=us-ascii
    Content-Disposition: inline
    <BLANKLINE>
    ping!
    <BLANKLINE>

    >>> verified
    False

    >>> for s in signatures:
    ...     print(s.dumps())  # doctest: +REPORT_UDIFF
    ... # doctest: +REPORT_UDIFF, +ELLIPSIS
    B2EDBE0E771A4B8708DD16A7511AEDA64332B6E3 signature:
      summary:
        CRL missing: False
        CRL too old: False
        bad policy: False
        green: False
        key expired: False
        key missing: False
        key revoked: False
        red: False
        signature expired: False
        system error: False
        valid: False
      status: success
      timestamp: Tue Apr 24 23:46:57 2012
      expiration timestamp: None
      wrong key usage: False
      pka trust: not available
      chain model: False
      validity: unknown
      validity reason: success
      public key algorithm: RSA
      hash algorithm: SHA1
    """
    content_type = message.get_content_type()
    if content_type == 'multipart/encrypted':
        _, body = _get_encrypted_parts(message)  # control
        encrypted = body.get_payload(decode=True)
        if not isinstance(encrypted, bytes):
            encrypted = encrypted.encode('us-ascii')
        decrypted, verified, message = verify_bytes(encrypted)
        return (message_from_bytes(decrypted), verified, message)
    body, signature = _get_signed_parts(message)
    sig_data = signature.get_payload(decode=True)
    if not isinstance(sig_data, bytes):
        sig_data = sig_data.encode('us-ascii')
    decrypted, verified, result = verify_bytes(
        _flatten(body), signature=sig_data, **kwargs
    )
    return (deepcopy(body), verified, result)
