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

from pgp.cipher import aidea

__all__ = ['aidea', 'camellia', 'twofish']


try:
    import camcrypt
    try:
        camcrypt.CamCrypt()
    except OSError:
        # On python3 the lib is not called camellia.so, but something
        # like camellia.cpython-34m.so. Use globbing to find a
        # candidate. This should be fixed upstream in the camcrypt
        # module instead.
        import glob
        import os
        sofile = glob.glob(os.path.join(camcrypt.__path__[0], 'camellia*.so'))[0]
        camcrypt.CamCrypt(libraryPath=sofile)
        camcrypt_kwargs = {'libraryPath': sofile}
    else:
        camcrypt_kwargs = {}
    HAS_CAMELLIA = True
except (ImportError, IndexError, OSError):
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
