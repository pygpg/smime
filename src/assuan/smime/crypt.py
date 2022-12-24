# Copyright (C) 2022 Jesse P. Johnson <jpj6652@gmail.com>
# Copyright (C) 2012 W. Trevor King <wking@tremily.us>
#
# This file is part of pgp-mime.
#
# pgp-mime is free software: you can redistribute it and/or modify it under the
# terms of the GNU General Public License as published by the Free Software
# Foundation, either version 3 of the License, or (at your option) any later
# version.
#
# pgp-mime is distributed in the hope that it will be useful, but WITHOUT ANY
# WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
# A PARTICULAR PURPOSE.  See the GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along with
# pgp-mime.  If not, see <http://www.gnu.org/licenses/>.

"""Encrypt and decrypt content using GPG."""

import configparser
import logging
import os
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Tuple

from assuan.client import AssuanClient
from assuan.common import Request, VarText

from .signature import verify_result_signatures

if TYPE_CHECKING:
    from configparser import ConfigParser
    from .signature import Signature

log = logging.getLogger(__name__)

uid = os.getuid()
# SOCKET_PATH = os.path.join(os.path.expanduser('~'), '.gnupg', 'S.gpgme-tool')
SOCKET_PATH = os.path.join(
    os.sep, 'run', 'user', str(uid), 'gnupg', 'S.gpg-agent'
)


def get_client_params(config: 'ConfigParser') -> Dict[str, Any]:
    r"""Retrieve Assuan client paramters from a config file.

    >>> from configparser import ConfigParser
    >>> from assuan.smime.crypt import SOCKET_PATH
    >>> config = ConfigParser()
    >>> config.read_string(
    ...     '\n'.join(
    ...         [
    ...             '[gpgme-tool]',
    ...             f"socket-path: /run/user/1000/gnupg/S.gpg-agent",
    ...         ]
    ...      )
    ... )
    >>> get_client_params(config)
    {'socket_path': '/run/user/1000/gnupg/S.gpg-agent'}

    >>> config = ConfigParser()
    >>> get_client_params(ConfigParser())
    {'socket_path': None}
    """
    params: Dict[str, Any] = {'socket_path': None}
    try:
        params['socket_path'] = config.get('gpgme-tool', 'socket-path')
    except configparser.NoSectionError:
        return params
    except configparser.NoOptionError:
        pass
    return params


def get_client(socket_path: Optional[str] = None) -> AssuanClient:
    """Get assuan client."""
    if socket_path is None:
        socket_path = SOCKET_PATH
    client = AssuanClient(name='assuan-smime', close_on_disconnect=True)
    client.connect(socket_path=socket_path)
    return client


def disconnect(client: AssuanClient) -> None:
    """Disconnect fro assuan server."""
    client.make_request(Request('BYE'))
    client.disconnect()


def hello(client: AssuanClient) -> None:
    # responses, data = client.get_responses()  # get initial 'OK' from server
    _, _ = client.get_responses()  # get initial 'OK' from server
    client.make_request(Request('ARMOR', 'true'))


def _read(desc, buffersize: int = 512):
    data = []
    while True:
        try:
            new = os.read(desc, buffersize)
        except Exception as err:
            log.warning('error while reading: %s', err)
            break
        if not new:
            break
        data.append(new)
    return b''.join(data)


def _write(desc, data):
    i = 0
    while i < len(data):
        i += os.write(desc, data[i:])


def sign_and_encrypt_bytes(
    data: VarText,
    signers: Optional[List[str]] = None,
    recipients: Optional[List[str]] = None,
    always_trust: bool = False,
    mode: str = 'detach',
    allow_default_signer: bool = False,
    **kwargs: Any,
):
    r"""Sign ``data`` with ``signers`` and encrypt to ``recipients``.

    Just sign (with a detached signature):

    >>> print(
    ...     sign_and_encrypt_bytes(
    ...         bytes(b'Hello'), signers=['assuan-smime@invalid.com']
    ...     )
    ... )
    ... # doctest: +ELLIPSIS
    b'-----BEGIN PGP SIGNATURE-----\n...-----END PGP SIGNATURE-----\n'

    Just encrypt:

    >>> sign_and_encrypt_bytes(
    ...     bytes(b'Hello'),
    ...     recipients=['assuan-smime@invalid.com'],
    ...     always_trust=True,
    ... )
    ... # doctest: +ELLIPSIS
    b'-----BEGIN PGP MESSAGE-----\n...-----END PGP MESSAGE-----\n'

    Sign and encrypt:

    >>> sign_and_encrypt_bytes(
    ...     bytes(b'Hello'),
    ...     signers=['assuan-smime@invalid.com'],
    ...     recipients=['assuan-smime@invalid.com'],
    ...     always_trust=True,
    ... )
    ... # doctest: +ELLIPSIS
    b'-----BEGIN PGP MESSAGE-----\n...-----END PGP MESSAGE-----\n'

    Sign and encrypt with a specific subkey:

    >>> sign_and_encrypt_bytes(
    ...     bytes(b'Hello'),
    ...     signers=['0x2F73DE2E'],
    ...     recipients=['assuan-smime@invalid.com'],
    ...     always_trust=True,
    ... )
    ... # doctest: +ELLIPSIS
    b'-----BEGIN PGP MESSAGE-----\n...-----END PGP MESSAGE-----\n'
    """
    input_read, input_write = os.pipe()
    output_read, output_write = os.pipe()
    client = get_client(**kwargs)

    try:
        # hello(client)
        if signers:
            for signer in signers:
                client.make_request(Request('SIGNER', signer))
        if recipients:
            for recipient in recipients:
                client.make_request(Request('RECIPIENT', recipient))

        client.send_fds([input_read])
        client.make_request(Request('INPUT', 'FD'))
        os.close(input_read)
        input_read = -1

        client.send_fds([output_write])
        client.make_request(Request('OUTPUT', 'FD'))
        os.close(output_write)
        output_write = -1

        parameters = []
        if signers or allow_default_signer:
            if recipients:
                command = 'SIGN_ENCRYPT'
            else:
                command = 'SIGN'
                parameters.append(f"--{mode}")
        elif recipients:
            command = 'ENCRYPT'
        else:
            raise ValueError('must specify at least one signer or recipient')

        if always_trust:
            parameters.append('--always-trust')

        _write(input_write, data)
        os.close(input_write)
        input_write = -1
        client.make_request(Request(command, ' '.join(parameters)))
        result = _read(output_read)
    finally:
        disconnect(client)
        for desc in [input_read, input_write, output_read, output_write]:
            if desc >= 0:
                os.close(desc)
    return result


def decrypt_bytes(data: bytes, **kwargs: Any) -> bytes:
    r"""Decrypt ``data``.

    >>> b = '\n'.join([
    ...     '-----BEGIN PGP MESSAGE-----',
    ...     'Version: GnuPG v2.0.17 (GNU/Linux)',
    ...     '',
    ...     'hQEMA1Ea7aZDMrbjAQf/TAqLjksZSJxSqkBxYT5gtLQoXY6isvRZg2apjs7CW0y2',
    ...     'tFK/ptnVYAq2OtWQFhbiJXj8hmwJyyFfb3lghpeu4ihO52JgkkwOpmJb6dxjOi83',
    ...     'qDwaGOogEPH38BNLuwdrMCW0jmNROwvS796PtqSGUaJTuIiKUB8lETwPwIHrDc11',
    ...     'N3RWStE5uShNkXXQXplUoeCKf3N4XguXym+GQCqJQzlEMrkkDdr4l7mzvt3Nf8EA',
    ...     'SgSak086tUoo9x8IN5PJCuOJkcXcjQzFcpqOsA7dyZKO8NeQUZv2JvlZuorckNvN',
    ...     'xx3PwW0a8VeJgTQrh64ZK/d3F3gNHUTzXkq/UIn25tJFAcmSUwxtsBal7p8zAeCV',
    ...     '8zefsHRQ5Y03IBeYBcVJBhDS9XfvwLQTJiGGstPCxzKTwSUT1MzV5t5twG/STDCc',
    ...     'uxW3wSdo',
    ...     '=bZI+',
    ...     '-----END PGP MESSAGE-----',
    ...     '',
    ... ]).encode('us-ascii')
    >>> decrypt_bytes(b)
    b'Success!\n'
    """
    input_read, input_write = os.pipe()
    output_read, output_write = os.pipe()
    client = get_client(**kwargs)

    try:
        # hello(client)
        client.send_fds([input_read])
        client.make_request(Request('INPUT', 'FD'))
        os.close(input_read)
        input_read = -1

        client.send_fds([output_write])
        client.make_request(Request('OUTPUT', 'FD'))
        os.close(output_write)
        output_write = -1

        _write(input_write, data)
        os.close(input_write)
        input_write = -1
        client.make_request(Request('DECRYPT'))
        result = _read(output_read)
    finally:
        disconnect(client)
        for desc in [input_read, input_write, output_read, output_write]:
            if desc >= 0:
                os.close(desc)
    return result


def verify_bytes(
    data: VarText,
    signature: Optional[str] = None,
    # always_trust: bool = False,
    **kwargs: Any,
) -> Tuple[VarText, bool, List['Signature']]:
    r"""Verify a signature on ``data``, possibly decrypting first.

    These tests assume you didn't trust the distributed test key.

    >>> b = '\n'.join(
    ...     [
    ...     '-----BEGIN PGP MESSAGE-----',
    ...     'Version: GnuPG v2.0.17 (GNU/Linux)',
    ...     '',
    ...     'hQEMA1Ea7aZDMrbjAQf/YM1SeFzNGz0DnUynaEyhfGCvcqmjtbN1PtZMpT7VaQLN',
    ...     'a+c0faskr79Atz0+2IBR7CDOlcETrRtH2EnrWukbRIDtmffNFGuhMRTNfnQ15OIN',
    ...     'qrmt2P5gXznsgnm2XjzTK7S/Cc3Aq+zjaDrDt7bIedEdz+EyNgaKuL/lB9cAB8xL',
    ...     'YYp/yn55Myjair2idgzsa7w/QXdE3RhpyRLqR2Jgz4P1I1xOgUYnylbpIZL9FOKN',
    ...     'NR3RQhkGdANBku8otfthb5ZUGsNMV45ct4V8PE+xChjFb9gcwpaf1hhoIF/sYHD5',
    ...     'Bkf+v/J8F40KGYY16b0DjQIUlnra9y7q9jj0h2bvc9LAtgHtVUso133LLcVYl7RP',
    ...     'Vjyz9Ps366BtIdPlAL4CoF5hEcMKS5J3h1vRlyAKN4uHENl5vKvoxn7ID3JhhWQc',
    ...     '6QrPGis64zi3OnYor34HPh/KNJvkgOQkekmtYuTxnkiONA4lhMDJgeaVZ9WZq+GV',
    ...     'MaCvCFGNYU2TV4V8wMlnUbF8d5bDQ83g8MxIVKdDcnBzzYLZha+qmz4Spry9iB53',
    ...     'Sg/sM5H8gWWSl7Oj1lxVg7o7IscpQfVt6zL6jD2VjL3L3Hu7WEXIrcGZtvrP4d+C',
    ...     'TGYWiGlh5B2UCFk2bVctfw8W/QfaVvJYD4Rfqta2V2p14KIJLFRSGa1g26W4ixrH',
    ...     'XKxgaA3AIfJ+6c5RoisRLuYCxvQi91wkE9hAXR+inXK4Hq4SmiHoeITZFhHP3hh3',
    ...     'rbpp8mopiMNxWqCbuqgILP6pShn4oPclu9aR8uJ1ziDxISTGYC71mvLUERUjFn2L',
    ...     'fu6C0+TCC9RmeyL+eNdM6cjs1G7YR6yX',
    ...     '=phHd',
    ...     '-----END PGP MESSAGE-----',
    ...     '',
    ...     ]
    ... ).encode('us-ascii')
    >>> output, verified, signatures = verify_bytes(b)
    >>> output
    b'Success!\n'

    >>> verified
    False

    >>> for s in signatures:
    ...     print(s.dumps())
    ... # doctest: +REPORT_UDIFF
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
      timestamp: Wed Mar 21 19:13:57 2012
      expiration timestamp: None
      wrong key usage: False
      pka trust: not available
      chain model: False
      validity: unknown
      validity reason: success
      public key algorithm: RSA
      hash algorithm: SHA256

    >>> b = b'Success!\n'
    >>> signature = '\n'.join(
    ...     [
    ...     '-----BEGIN PGP SIGNATURE-----',
    ...     'Version: GnuPG v2.0.17 (GNU/Linux)',
    ...     '',
    ...     'iQEcBAEBAgAGBQJPaiw/AAoJEFEa7aZDMrbj93gH/1fQPXLjUTpONJUTmvGoMLNA',
    ...     'W9ZhjpUL5i6rRqYGUvQ4kTEDuPMxkMrCyFCDHEhSDHufMek6Nso5/HeJn3aqxlgs',
    ...     'hmNlvAq4FI6JQyFL7eCp/XG9cPx1p42dTI7JAih8FuK21sS4m/H5XP3R/6KXC99D',
    ...     '39rrXCvvR+yNgKe2dxuJwmKuLteVlcWxiIQwVrYK70GtJHC5BO79G8yGccWoEy9C',
    ...     '9JkJiyNptqZyFjGBNmMmrCSFZ7ZFA02RB+laRmwuIiozw4TJYEksxPrgZMbbcFzx',
    ...     'zs3JHyV23+Fz1ftalvwskHE7tJkX9Ub8iBMNZ/KxJXXdPdpuMdEYVjoUehkQBQE=',
    ...     '=rRBP',
    ...     '-----END PGP SIGNATURE-----',
    ...     '',
    ...     ]
    ... ).encode('us-ascii')
    >>> output, verified, signatures = verify_bytes(b, signature=signature)
    >>> output
    b'Success!\n'

    >>> verified
    False

    >>> for s in signatures:
    ...     print(s.dumps())
    ... # doctest: +REPORT_UDIFF
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
      timestamp: Wed Mar 21 19:30:07 2012
      expiration timestamp: None
      wrong key usage: False
      pka trust: not available
      chain model: False
      validity: unknown
      validity reason: success
      public key algorithm: RSA
      hash algorithm: SHA1

    Data signed by a subkey returns the subkey fingerprint.  To find
    the primary key for a given subkey, use
    ``assuan.smime.key.lookup_keys()``.

    >>> b = '\n'.join(
    ...     [
    ...     '-----BEGIN PGP MESSAGE-----',
    ...     'Version: GnuPG v2.0.19 (GNU/Linux)',
    ...     '',
    ...     'hQEMAxcQCLovc94uAQf9ErTZnr0lYRlLLZIk1VcpNNTHrMro+BmqpFC0jprA4/2m',
    ...     '92klBF4TIS1A9bU5oxzQquaAIDV42P3sXrbxu/YhHLmPGH+dc2JVSfPLL0XOL5GC',
    ...     'qpQYe5lglRBReFSRktrfhukjHBoXvh3c8T4xYK2r+nIV4gsp+FrSQMIOdhhBoC36',
    ...     'U1MOk+R+I0JDbWdzZzJONs7ZcAcNDVKqxmAXZUqVgkhPpnGBSBuF9ExKRT3S6e5N',
    ...     'Rsorb/DjGIUHSZuH2EaWAUz1jJ3nSta7TnveT/avfJiAV7cRS4oVgyyFyuHO5gkI',
    ...     'o0obeJaut3enVgpq2TUUk0M4L8TX4jjKvDGAYNyuPNLAsQFHLj5eLmJSudGStWuA',
    ...     'WjKLqBHD0M8/OcwnrTMleJl+h50ZsHO1tvvkXelH+w/jD5SMS+ktxq2Te8Vj7BmM',
    ...     '0WQn3Ys7ViA5PgcSpbqNNLdgc1EMcpPI/sfJAORPKVWRPBKDXX/irY2onAMSe5gH',
    ...     'teNX6bZd/gaoLWqD/1ZhsOCnlV7LY1R929TJ9vxnJcfKKAKwBDfAaSbecUUMECVw',
    ...     's4u3ZT1pmNslBmH6XSy3ifLYWu/2xsJuhPradT88BJOBARMGg81gOE6zxGRrMLJa',
    ...     'KojFgqaF2y4nlZAyaJ1Ld4qCaoQogaL9qE1BbmgtBehZ2FNQiIBSLC0fUUl8A4Py',
    ...     '4d9ZxUoSp7nZmgTN5pUH1N9DIC4ntp/Rak2WnpS7+dRPlp9A2SF0RkeLY+JD9gNm',
    ...     'j44zBkI79KlgaE/cMt6xUXAF/1ZR/Hv/6GUazGx0l23CnSGuqzLpex2uKOxfKiJt',
    ...     'jfgyZRhIdFJnRuEXt8dTTDiiYA==',
    ...     '=0o+x',
    ...     '-----END PGP MESSAGE-----',
    ...     '',
    ...     ]
    ... ).encode('us-ascii')
    >>> output, verified, signatures = verify_bytes(b)
    >>> output
    b'Hello'

    >>> verified
    False

    >>> for s in signatures:
    ...     print(s.dumps())
    ... # doctest: +REPORT_UDIFF
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
      timestamp: Thu Sep 20 15:29:28 2012
      expiration timestamp: None
      wrong key usage: False
      pka trust: not available
      chain model: False
      validity: unknown
      validity reason: success
      public key algorithm: RSA
      hash algorithm: SHA256
    """
    input_read, input_write = os.pipe()
    if signature:
        message_read, message_write = os.pipe()
        output_read = output_write = -1
    else:
        message_read = message_write = -1
        output_read, output_write = os.pipe()

    client = get_client(**kwargs)
    verified = None
    signatures = []

    try:
        # hello(client)
        client.send_fds([input_read])
        client.make_request(Request('INPUT', 'FD'))
        os.close(input_read)
        input_read = -1

        if signature:
            client.send_fds([message_read])
            client.make_request(Request('MESSAGE', 'FD'))
            os.close(message_read)
            message_read = -1
        else:
            client.send_fds([output_write])
            client.make_request(Request('OUTPUT', 'FD'))
            os.close(output_write)
            output_write = -1

        if signature:
            _write(input_write, signature)
            os.close(input_write)
            input_write = -1

            _write(message_write, data)
            os.close(message_write)
            message_write = -1
        else:
            _write(input_write, data)
            os.close(input_write)
            input_write = -1

        client.make_request(Request('VERIFY'))
        if signature:
            plain = data
        else:
            plain = _read(output_read)

        _, result = client.make_request(Request('RESULT'))
        signatures = list(verify_result_signatures(result))
        verified = True

        for sig in signatures:
            if sig.status != 'success':
                verified = False
            elif sig.pka_trust != 'good':
                verified = False
    finally:
        disconnect(client)
        for desc in [
            input_read,
            input_write,
            message_read,
            message_write,
            output_read,
            output_write,
        ]:
            if desc >= 0:
                os.close(desc)
    return (plain, verified, signatures)
