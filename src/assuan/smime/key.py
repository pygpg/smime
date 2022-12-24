# Copyright (C) 2022 Jesse P. Johnson <jpj6652@gmail.com>
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

"""Manage keys."""

import logging
from functools import total_ordering
from typing import Any, Generator, List, Optional
from xml.etree import ElementTree

from assuan.common import Request

from . import crypt

log = logging.getLogger(__name__)


@total_ordering
class SubKey:
    """The crypographic key portion of an OpenPGP key."""

    def __init__(self, fingerprint: Optional[str] = None) -> None:
        self.fingerprint = fingerprint

    def __str__(self) -> str:
        if self.fingerprint:
            return f"<{type(self).__name__} {self.fingerprint[-8:]}>"
        return f"<{type(self).__name__}>"

    def __repr__(self) -> str:
        return str(self)

    def __eq__(self, other: object) -> bool:
        if self.fingerprint and hasattr(other, 'fingerprint'):
            return self.fingerprint == other.fingerprint
        return id(self) == id(other)

    def __lt__(self, other: object) -> bool:
        if self.fingerprint and hasattr(other, 'fingerprint'):
            return self.fingerprint < other.fingerprint
        return id(self) < id(other)

    # def __hash__(self) -> int:
    #     return int(self.fingerprint, 16)


@total_ordering
class UserID:
    """The user ID of the email."""

    def __init__(
        self,
        uid: Optional[str] = None,
        name: Optional[str] = None,
        email: Optional[str] = None,
        comment: Optional[str] = None,
    ) -> None:
        self.uid = uid
        self.name = name
        self.email = email
        self.comment = comment

    def __str__(self) -> str:
        return f"<{type(self).__name__} {self.name}>"

    def __repr__(self) -> str:
        return str(self)

    def __eq__(self, other: object) -> bool:
        if self.uid and hasattr(other, 'uid'):
            return self.uid == other.uid
        return id(self) == id(other)

    def __lt__(self, other: object) -> bool:
        if self.uid and hasattr(other, 'uid'):
            return self.uid < other.uid
        return id(self) < id(other)

    # def __hash__(self) -> int:
    #     return hash(self.uid)


@total_ordering
class Key:
    """The signing key for PGP."""

    def __init__(
        self, subkeys: Optional[Any] = None, uids: Optional[Any] = None
    ) -> None:
        self.revoked = False
        self.expired = False
        self.disabled = False
        self.invalid = False
        self.can_encrypt = False
        self.can_sign = False
        self.can_certify = False
        self.can_authenticate = False
        self.is_qualified = False
        self.secret = False
        self.protocol = None
        self.issuer = None
        self.chain_id = None
        self.owner_trust = None

        if subkeys is None:
            subkeys = []
        self.subkeys = subkeys

        if uids is None:
            uids = []
        self.uids = uids

    def __str__(self) -> str:
        return f"<{type(self).__name__} {self.subkeys[0].fingerprint[-8:]}>"

    def __repr__(self) -> str:
        return str(self)

    def __eq__(self, other: object) -> bool:
        other_subkeys = getattr(other, 'subkeys', None)
        if self.subkeys and other_subkeys and isinstance(other, type(self)):
            return self.subkeys[0] == other.subkeys[0]
        return id(self) == id(other)

    def __lt__(self, other: 'Key') -> bool:
        other_subkeys = getattr(other, 'subkeys', None)
        if self.subkeys and other_subkeys:
            return self.subkeys[0] < other.subkeys[0]
        return id(self) < id(other)

    # def __hash__(self) -> int:
    #     return int(self.fingerprint, 16)


def lookup_keys(
    patterns: Optional[List[str]] = None, **kwargs: Any
) -> Generator['Key', None, None]:
    """Lookup keys matching any patterns listed in ``patterns``.

    >>> import pprint

    >>> key = list(lookup_keys(['assuan-smime-test']))[0]
    >>> key
    <Key 4332B6E3>

    >>> key.subkeys
    [<SubKey 4332B6E3>, <SubKey 2F73DE2E>]

    >>> key.uids
    [<UserID assuan-smime-test>]

    >>> key.uids[0].uid
    'assuan-smime-test (http://blog.tremily.us/posts/assuan-smime/) <assuan-smime@invalid.com>'

    >>> key.can_encrypt
    True

    >>> key.protocol
    'OpenPGP'

    >>> print(list(lookup_keys(['assuan-smime-test'])))
    [<Key 4332B6E3>]

    >>> print(list(lookup_keys(['assuan-smime@invalid.com'])))
    [<Key 4332B6E3>]

    >>> print(list(lookup_keys(['4332B6E3'])))
    [<Key 4332B6E3>]

    >>> print(list(lookup_keys(['0x2F73DE2E'])))
    [<Key 4332B6E3>]

    >>> print(list(lookup_keys()))  # doctest: +ELLIPSIS
    [..., <Key 4332B6E3>, ...]
    """
    log.debug('lookup key: %s', patterns)
    client = crypt.get_client(**kwargs)
    # parameters = []

    if patterns:
        args = [' '.join(patterns)]
    else:
        args = []

    try:
        crypt.hello(client)
        _, result = client.make_request(Request('KEYLIST', *args))  # rs
    finally:
        crypt.disconnect(client)

    tag_mapping = {}
    tree = ElementTree.fromstring(result.replace(b'\x00', b''))
    for key in tree.findall('.//key'):
        k = Key()
        for child in key:
            attribute = tag_mapping.get(child.tag, child.tag.replace('-', '_'))
            if child.tag in [
                'revoked',
                'expired',
                'disabled',
                'invalid',
                'can-encrypt',
                'can-sign',
                'can-certify',
                'can-authenticate',
                'is-qualified',
                'secret',
                'revoked',
            ]:
                # boolean values
                value = child.get('value')
                if not value.startswith('0x'):
                    raise NotImplementedError(f"{child.tag} value {value}")
                value = int(value, 16)
                value = bool(value)
            elif child.tag in ['protocol', 'owner-trust']:
                value = child.text
            elif child.tag in ['issuer', 'chain-id']:
                # ignore for now
                pass
            elif child.tag in ['subkeys', 'uids']:
                parser = globals()[f"_parse_{attribute}"]
                value = parser(child)
            else:
                raise NotImplementedError(child.tag)
            setattr(k, attribute, value)
        yield k


def _parse_subkeys(element):
    tag_mapping = {
        'fpr': 'fingerprint',
    }
    subkeys = []
    for subkey in element:
        s = SubKey()
        for child in subkey.iter():
            if child == subkey:  # iter() includes the root element
                continue
            attribute = tag_mapping.get(child.tag, child.tag.replace('-', '_'))
            if child.tag in ['fpr']:
                value = child.text
            else:
                raise NotImplementedError(child.tag)
            setattr(s, attribute, value)
        subkeys.append(s)
    return subkeys


def _parse_uids(element):
    tag_mapping = {}
    uids = []
    for uid in element:
        user_id = UserID()
        for child in uid.iter():
            if child == uid:  # iter() includes the root element
                continue
            attribute = tag_mapping.get(child.tag, child.tag.replace('-', '_'))
            if child.tag in ['uid', 'name', 'email', 'comment']:
                value = child.text
            else:
                raise NotImplementedError(child.tag)
            setattr(user_id, attribute, value)
        uids.append(user_id)
    return uids
