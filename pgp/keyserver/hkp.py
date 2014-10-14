# python-pgp A Python OpenPGP implementation
# Copyright (C) 2014 Richard Mitchell
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import datetime
import time
from urllib.parse import unquote
from urllib.parse import urljoin
from urllib.parse import urlparse
from urllib.parse import urlunparse

import requests

from pgp import armor
from pgp.shortcuts import read_key


def _add_colons(line, number):
    # "Colons for empty fields on the end of each line may be left off, if
    #  desired."
    count = len([c for c in line if c == ':'])
    for i in range(number - count):
        line += ':'
    return line


class HKPUserIdResult(object):

    def __repr__(self):
        return '<{name} {uid} for {key_id} at 0x{pos:012x}>'.format(
            name=self.__class__.__name__,
            uid=repr(self.user_id),
            key_id=self.result.key_id,
            pos=id(self)
            )

    def __init__(self, result, uid_line):
        self.result = result
        self._parse_uid_line(uid_line)

    def _parse_uid_line(self, l):
        l = _add_colons(l, 4)
        _uid, uid, created, expires, flags = l.split(':')
        self.user_id = unquote(uid)
        self.created = datetime.datetime.fromtimestamp(int(created))
        if expires:
            self.expires = datetime.datetime.fromtimestamp(int(expires))
        else:
            self.expires = None
        self.revoked = 'r' in flags
        self.disabled = 'd' in flags
        self.expired = 'e' in flags


class HKPResult(object):

    def __repr__(self):
        return '<{name} {key_id} {uid} at 0x{pos:012x}>'.format(
            name=self.__class__.__name__,
            key_id=self.key_id,
            uid=(
                repr(self.user_ids[0].user_id)
                if self.user_ids else '-No user ID-'
                ),
            pos=id(self))

    def __init__(self, server, pub_line, uid_lines):
        self.server = server
        self._parse_pub_line(pub_line)
        self.user_ids = []
        for l in uid_lines:
            self.user_ids.append(HKPUserIdResult(self, l))

    def _parse_pub_line(self, l):
        l = _add_colons(l, 6)
        (_pub, key_id, public_key_algorithm, bit_length,
            created, expires, flags) = l.split(':')
        self.key_id = key_id
        self.public_key_algorithm = int(public_key_algorithm)
        self.bit_length = int(bit_length)
        self.created = datetime.datetime.fromtimestamp(int(created))
        if expires:
            self.expires = datetime.datetime.fromtimestamp(int(expires))
        else:
            self.expires = None
        self.revoked = 'r' in flags
        self.disabled = 'd' in flags
        self.expired = 'e' in flags

    def get(self):
        return self.server.get(self.key_id)


class HKPKeyserverClient(object):

    def __repr__(self):
        return '<{name} {url} at 0x{pos:012x}>'.format(
            name=self.__class__.__name__,
            url=self.base_url,
            pos=id(self))

    def __init__(self, base_url):
        parts = urlparse(base_url)
        base_url = urlunparse(
            (('https' if parts.scheme.lower() == 'hkps' else 'http'),)
            + parts[1:6])
        self.base_url = base_url

    @property
    def get_url(self):
        return urljoin(self.base_url, 'pks/lookup')

    @property
    def submit_url(self):
        return urljoin(self.base_url, 'pks/add')

    def _read_mr(self, data):
        data = data.splitlines()
        info_line = data[0]
        if info_line.startswith('info:'):
            _info, version, count = info_line.split(':')
        else:
            version = 1
            count = None

        results = []
        pub_key = None
        user_ids = []
        for line in data:
            if line.startswith('pub'):
                if pub_key:
                    results.append(HKPResult(self, pub_key, user_ids))
                pub_key = line
                user_ids = []
            elif line.startswith('uid'):
                user_ids.append(line)
            # Skip anything else

        if pub_key:
            results.append(HKPResult(self, pub_key, user_ids))

        return results

    def get(self, key_id, exact=False):
        response = requests.get(self.get_url, params={
            'op': 'get',
            'search': '0x{}'.format(key_id),
            'options': 'mr',
            'exact': 'yes' if exact else 'no',
            })
        response.raise_for_status()
        return read_key(response.content, True)

    def search(self, terms, exact=False):
        response = requests.get(self.get_url, params={
            'op': 'index',
            'options': 'mr',
            'search': terms,
            'exact': 'yes' if exact else 'no'
            })
        response.raise_for_status()
        return self._read_mr(response.text)

    def submit(self, key, no_modify=False):
        key_data = b''.join(map(bytes, key.to_packets()))
        a = armor.ASCIIArmor(armor.PGP_PUBLIC_KEY_BLOCK, key_data)
        response = requests.post(self.submit_url, data={
            'keytext': str(a),
            'options': 'mr,nm' if no_modify else 'mr',
            })
        response.raise_for_status()
