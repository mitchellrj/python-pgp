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

from __future__ import absolute_import


__all__ = ['camellia', 'twofish']


try:
    import camcrypt
    camcrypt.CamCrypt()
    HAS_CAMELLIA = True
except (ImportError, OSError):
    HAS_CAMELLIA = False


try:
    import twofish as _twofish
    HAS_TWOFISH = True
except ImportError:
    HAS_TWOFISH = False


if HAS_CAMELLIA:
    from pgp.cipher import camellia
else:
    camellia = None


if HAS_TWOFISH:
    from pgp.cipher import twofish
else:
    twofish = None
