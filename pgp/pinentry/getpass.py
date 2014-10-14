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

from getpass import getpass
import sys


class GetPassPinentry(object):

    def __init__(self):
        self._cache = {}

    def get_passphrase(self, prompt=None, error_message=None,
                       description=None, cache_id=None, use_cache=True,
                       no_ask=False, qualitybar=False, repeat=0,
                       stream=sys.stdout):
        if prompt in (None, 'X'):
            # Default prompt
            prompt = 'PIN?'
        if error_message in (None, 'X'):
            error_message = 'Error.'
        if description in (None, 'X'):
            description = ''
        if cache_id == 'X':
            cache_id = None

        if use_cache and cache_id and cache_id in self._cache:
            return self._cache[cache_id]

        if no_ask:
            raise KeyError(cache_id)

        if prompt:
            print(prompt, file=stream)
        if description:
            print(description, file=stream)

        match = False
        while not match:
            match = True
            if error_message:
                print(error_message, file=stream)
            passphrase = getpass('Password: ', stream=stream)
            for _i in range(repeat):
                if getpass('Confirm: ', stream=stream) != passphrase:
                    match = False
                    error_message = 'Passwords do not match.'

        if use_cache and cache_id:
            self._cache[cache_id] = passphrase
        return passphrase

    def clear_passphrase(self, cache_id):
        while cache_id in self._cache:
            del self._cache[cache_id]
