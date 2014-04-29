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

import pgpdump

from pgp.merge import key_to_merge_updates
from pgp.parse import parse
from pgp.signature_verification import validate_signatures


def add_keys_merge(parser, db):
    for key_data in parse(parser):
        validate_signatures(key_data, db)
        key_data = key_to_merge_updates(key_data, db)

        if key_data:
            public_key = db.create_key(key_data)
            yield public_key


def add_keys_merge_binary(data, db):
    parser = pgpdump.BinaryData(data)
    public_keys = add_keys_merge(parser, db)
    return public_keys


def add_keys_merge_ascii(data, db):
    parser = pgpdump.AsciiData(data)
    public_keys = add_keys_merge(parser, db)
    return public_keys
