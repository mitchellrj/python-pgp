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

import atexit
from collections import OrderedDict
try:
    from dbm import gnu as gdbm
    HAVE_GDBM = True
except ImportError:
    try:
        import gdbm
        HAVE_GDBM = True
    except (ImportError, OSError):
        HAVE_GDBM = False
import os
import platform
import signal
import threading
import time

from pgp.packets import parse_binary_packet_data
from pgp.packets import parse_binary_packet_stream
from pgp.packets import constants
from pgp.transferrable_keys import TransferablePublicKey
from pgp.transferrable_keys import TransferableSecretKey


GDBM_MAGIC = (
    b'\x13\x57\x9a\xce'
    b'\xce\x9a\x57\x13'
)


DEFAULT_RESOURCES = (
    (
        os.path.expanduser(os.path.join(
            '~', '.gnupg', 'secring{0}gpg'.format(os.path.extsep))),
        True
    ),
    (
        os.path.expanduser(os.path.join(
            '~', '.gnupg', 'pubring{0}gpg'.format(os.path.extsep))),
        False
    ),
)


_locks = []


@atexit.register
def _clean_up_locks():
    for l in _locks:
        l.release()
        try:
            os.unlink(l.name)
        except:
            pass
        try:
            os.unlink(l.lock_template_name)
        except:
            pass


class Lock(object):

    name = None
    template_name = None
    locked = False

    def __init__(self, filename):
        node_name = platform.node()
        dirpart = os.path.dirname(filename)
        self.template_name = '{0}{1}.#lk{2:x}.'.format(
            dirpart,
            os.path.sep,
            id(self)
            )
        with open(self.template_name, 'w') as lock_fh:
            lock_fh.write('{0:010d}'.format(os.getpid()))
            lock_fh.write(node_name)
            lock_fh.write('\n')
        self.name = '{0}{1}lock'.format(
            filename,
            os.path.extsep)
        self._lock = threading.RLock()
        _locks.append(self)

    def __del__(self):
        try:
            self.release()
            os.unlink(self.lock_template_name)
        except:
            # TODO: log an error
            pass

    def read(self):
        with open(self.name, 'r') as fh:
            pid = int(fh.read(10))
            node = fh.read().strip()

        return pid, node == platform.node()

    def acquire(self, timeout=None):
        start = time.time()
        while not self.locked:
            if timeout is not None and (time.time() - start) > timeout:
                return False
            self._lock.acquire()
            os.link(self.template_name, self.name)
            pid, same_node = self.read()
            if pid == os.getpid() and same_node:
                # OK
                pass
            elif same_node:
                # attempt to kill the interloper
                os.kill(pid, signal.SIG_DFL)
                os.unlink(self.name)
                continue
            self.locked = True

        return True

    def release(self):
        if not self.locked:
            return

        pid, same_node = self.read()
        if pid == os.getpid() and same_node:
            os.unlink(self.name)
            self.locked = False
            self._lock.release()
        else:
            # TODO: error?
            return


class ResourceTypes:

    NONE = 0
    KEYRING = 1
    KEYBOX = 2
    GDBM = 3


class BaseResource(object):

    def __init__(self, filename, force, secret, read_only, default):
        self.filename = filename
        self._lock = Lock(self.filename)
        self.secret = secret
        self.read_only = read_only
        self.default = default
        self._maybe_create(force)

    def items(self):
        for k in self.keys():
            yield k, self.get_transferrable_key(k)

    def values(self):
        for k in self.keys():
            yield self.get_transferrable_key(k)

    def __iter__(self):
        return self.keys()

    def __contains__(self, fingerprint):
        return fingerprint in self.keys()

    def lock_db(self):
        self._lock.acquire()

    def unlock_db(self):
        self._lock.release()

    def _maybe_create(self, force):
        if not os.path.exists(self.filename):
            if force:
                self.create_db(self.filename)
            else:
                raise RuntimeError(
                    'Database {0} does not exist.'.format(self.filename))


class GDBM(BaseResource):

    def __init__(self, *args, **kwargs):
        super(GDBM, self).__init__(*args, **kwargs)
        first_key = self.firstkey()
        if first_key is not None:
            packet = next(parse_binary_packet_data(self[first_key]))
            self._preferred_header_format = packet.header_format
        else:
            self._preferred_header_format = constants.OLD_PACKET_HEADER_TYPE

    def keys(self):
        self.lock_db()
        try:
            with gdbm.open(self.filename, 'r') as db:
                key = db.firstkey()
                while key is not None:
                    yield key
                    key = db.nextkey(key)
        finally:
            self.unlock_db()

    def create_db(self):
        self.lock_db()
        try:
            with gdbm.open(self.filename, 'c'):
                os.chmod(self.filename, 0o600)
        finally:
            self.unlock_db()

    def get_transferrable_key(self, fingerprint):
        if len(fingerprint) != 40:
            # Actually a key ID - find the fingerprint first.
            fingerprint = ([
                k for k in self.keys()
                if k.endswith(fingerprint)
                ] + [None]
                )[0]

        if fingerprint is None:
            return None

        self.lock_db()
        try:
            with gdbm.open(self.filename, 'r') as db:
                packet_data = db[fingerprint]
            packets = list(parse_binary_packet_data(packet_data))
            if packets:
                if packets[0].type == constants.PUBLIC_KEY_PACKET_TYPE:
                    return TransferablePublicKey.from_packets(packets)
                elif packets[0].type == constants.SECRET_KEY_PACKET_TYPE:
                    return TransferableSecretKey.from_packets(packets)
        finally:
            self.unlock_db()

    def add_transferrable_key(self, key):
        if self.read_only:
            raise TypeError

        self.lock_db()
        try:
            with gdbm.open(self.filename, 'w') as db:
                if key.fingerprint in db:
                    raise KeyError(key.fingerprint)
                db[key.fingerprint] = \
                    b''.join(map(bytes, key.to_packets(
                        self._preferred_header_format)))
        finally:
            self.unlock_db()

    def update_transferrable_key(self, key):
        # Delete and add in one operation
        if self.read_only:
            raise TypeError

        self.lock_db()
        try:
            with gdbm.open(self.filename, 'w') as db:
                if key.fingerprint not in db:
                    raise KeyError(key.fingerprint)
                db[key.fingerprint] = \
                    b''.join(map(bytes, key.to_packets(
                        self._preferred_header_format)))
        finally:
            self.unlock_db()

    def delete_transferrable_key(self, key):
        if self.read_only:
            raise TypeError

        self.lock_db()
        try:
            with gdbm.open(self.filename, 'w') as db:
                if key.fingerprint not in db:
                    raise KeyError(key.fingerprint)
                gdbm.reorganize()
                del db[key.fingerprint]
        finally:
            self.unlock_db()


class Keyring(BaseResource):

    _offset_table = None

    def __init__(self, filename, force, secret, read_only, default):
        super(Keyring, self).__init__(filename, force, secret, read_only,
                                      default)
        self._preferred_header_format = None
        self._update_offset_table()

    def keys(self):
        return self._offset_table.keys()

    def _update_offset_table(self):
        offset_table = {}
        self.lock_db()
        try:
            with open(self.filename, 'rb') as fh:
                packet_iter = parse_binary_packet_stream(fh)
                last_offset = fh.tell()
                for packet in packet_iter:
                    if self._preferred_header_format is None:
                        self._preferred_header_format = packet.header_format
                    if packet.type in (
                            constants.PUBLIC_KEY_PACKET_TYPE,
                            constants.SECRET_KEY_PACKET_TYPE,
                            ):
                        offset_table[packet.key_id[-8:]] = last_offset
                    last_offset = fh.tell()
        finally:
            self.unlock_db()

        self._offset_table = offset_table

    def _get_key(self, offset):
        self.lock_db()
        try:
            with open(self.filename, 'rb') as fh:
                fh.seek(offset)
                packets = []
                packet_iter = parse_binary_packet_stream(fh)
                for packet in packet_iter:
                    if packet.type == constants.COMPRESSED_DATA_PACKET_TYPE:
                        continue
                    elif packets and packet.type in (
                            constants.PUBLIC_KEY_PACKET_TYPE,
                            constants.SECRET_KEY_PACKET_TYPE,
                            ):
                        break
                    else:
                        packets.append(packet)
        finally:
            self.unlock_db()

        key = None
        if packets and packets[0].type == constants.PUBLIC_KEY_PACKET_TYPE:
            key = TransferablePublicKey.from_packets(packets)
        elif packets and packets[0].type == constants.SECRET_KEY_PACKET_TYPE:
            key = TransferableSecretKey.from_packets(packets)
        elif packets:
            raise ValueError(packets[0])
        else:
            raise KeyError()

        return key

    def create_db(self):
        self.lock_db()
        try:
            with open(self.filename, 'wb'):
                os.chmod(self.filename, 0o600)
        finally:
            self.unlock_db()

    def get_transferrable_key(self, fingerprint):
        offset = self._offset_table[fingerprint[-8:]]
        return self._get_key(offset)

    def add_transferrable_key(self, key):
        if self.read_only:
            raise TypeError

        if key.fingerprint in self._offset_table:
            raise KeyError

        self.lock_db()
        try:
            data = b''
            with open(self.filename, 'rb') as fh:
                data = fh.read()

            data += b''.join(map(bytes, key.to_packets(
                self._preferred_header_format)))
            with open(self.filename, 'wb') as fh:
                fh.write(data)
            self._update_offset_table()
        finally:
            self.unlock_db()

    def update_transferrable_key(self, key):
        # Delete and add in one operation

        if self.read_only:
            raise TypeError

        if key.fingerprint[-8:] not in self._offset_table:
            raise KeyError

        offset = self._offset_table[key.fingerprint[-8:]]
        self.lock_db()
        try:
            data = b''
            with open(self.filename, 'rb') as fh:
                data = fh.read(offset)
                packets = []
                packet_iter = parse_binary_packet_stream(fh)
                header_format = None
                for packet in packet_iter:
                    if header_format is None:
                        header_format = packet.header_format
                    if packets and packet.type in (
                            constants.PUBLIC_KEY_PACKET_TYPE,
                            constants.SECRET_KEY_PACKET_TYPE,
                            ):
                        break
                    last_offset = fh.tell()
                fh.seek(last_offset)
                data += fh.read()
            data += b''.join(map(bytes, key.to_packets(header_format)))
            with open(self.filename, 'wb') as fh:
                fh.write(data)
            self._update_offset_table()
        finally:
            self.unlock_db()

    def delete_transferrable_key(self, key):
        if self.read_only:
            raise TypeError

        if key.fingerprint[-8:] not in self._offset_table:
            raise KeyError

        offset = self._offset_table[key.fingerprint[-8:]]
        self.lock_db()
        try:
            data = b''
            with open(self.filename, 'rb') as fh:
                data = fh.read(offset)
                packets = []
                packet_iter = parse_binary_packet_stream(fh)
                header_format = None
                for packet in packet_iter:
                    if header_format is None:
                        header_format = packet.header_format
                    if packets and packet.type in (
                            constants.PUBLIC_KEY_PACKET_TYPE,
                            constants.SECRET_KEY_PACKET_TYPE,
                            ):
                        break
                    last_offset = fh.tell()
                fh.seek(last_offset)
                data += fh.read()
            with open(self.filename, 'wb') as fh:
                fh.write(data)
            self._update_offset_table()
        finally:
            self.unlock_db()


def get_resource(filename, force=False, secret=False, read_only=False,
                 default=False):

    type_ = ResourceTypes.NONE
    if filename.startswith('gnupg-keyring:'):
        type_ = ResourceTypes.KEYRING
        filename = filename[12:]
    elif filename.startswith('gnupg-kbx:'):
        type_ = ResourceTypes.KEYBOX
        filename = filename[11:]
    filename = os.path.abspath(filename)

    if type_ == ResourceTypes.NONE:
        magic = None
        try:
            fh = open(filename, 'rb')
            magic = fh.read(4)
        except OSError:
            type_ = ResourceTypes.KEYRING
        else:
            if magic in GDBM_MAGIC:
                type_ = ResourceTypes.GDBM
            elif fh.read(4)[:1] == b'\x01' and fh.read(4) == b'KBXf':
                type_ = ResourceTypes.KEYBOX
            else:
                type_ = ResourceTypes.KEYRING
            fh.close()

    if type_ == ResourceTypes.KEYBOX:
        raise ValueError('Unsupported resource type, Keybox')
    elif type_ == ResourceTypes.KEYRING:
        return Keyring(filename, force, secret, read_only, default)
    elif type_ == ResourceTypes.GDBM:
        if HAVE_GDBM:
            return GDBM(filename, force, secret, read_only, default)
        else:
            raise RuntimeError()
    else:
        raise ValueError('Unknown resource type')


class GPGDatabase(object):

    _resources = None

    def __init__(self):
        self._resources = OrderedDict()

    def load_default_resources(self, force=False, read_only=False):
        for (filename, secret) in DEFAULT_RESOURCES:
            self.add_resource(filename, force=force, primary=False,
                              default=True, read_only=read_only,
                              secret=secret)

    def add_resource(self, filename, force=False, primary=False,
                     default=False, read_only=False, secret=False):
        resource = get_resource(filename, force, secret, read_only, default)
        resource = self.register_resource(resource.filename, resource, primary)
        return resource

    def add_key(self, key):
        if isinstance(key, TransferablePublicKey):
            for resource in self._resources.values():
                if not resource.secret:
                    resource.add_transferrable_key(key)
                    break
        elif isinstance(key, TransferableSecretKey):
            for resource in self._resources.values():
                if resource.secret:
                    resource.add_transferrable_key(key)
                    break
        else:
            raise TypeError

    def delete_key(self, key):
        if isinstance(key, TransferablePublicKey):
            for resource in self._resources.values():
                if not resource.secret:
                    resource.delete_transferrable_key(key)
                    break
        elif isinstance(key, TransferableSecretKey):
            for resource in self._resources.values():
                if resource.secret:
                    resource.delete_transferrable_key(key)
                    break
        else:
            raise TypeError

    def update_key(self, key):
        if isinstance(key, TransferablePublicKey):
            for resource in self._resources.values():
                if not resource.secret:
                    resource.update_transferrable_key(key)
                    break
        elif isinstance(key, TransferableSecretKey):
            for resource in self._resources.values():
                if resource.secret:
                    resource.update_transferrable_key(key)
                    break
        else:
            raise TypeError

    def register_resource(self, name, resource, primary):
        resource = self._resources.setdefault(name, resource)
        if primary:
            self._resources.move_to_end(name, last=False)
        return resource

    def _matches_user_id(self, key, user_id):
        match = False
        for uid in key.user_ids:
            if user_id.lower() in uid.user_id.lower():
                match = True
                break
        return match

    def keys(self):
        for resource in self._resources.values():
            yield from resource.keys()

    def search(self, fingerprint=None, key_id=None, user_id=None):
        results = []
        if fingerprint is None and key_id is None and user_id is None:
            return results
        for resource in self._resources.values():
            if fingerprint or key_id:
                try:
                    key = resource.get_transferrable_key(fingerprint or key_id)
                except KeyError:
                    continue
                if user_id is not None:
                    if self._matches_user_id(key, user_id):
                        results.append(key)
                else:
                    results.append(key)
            else:
                # User ID only. Be really dumb and iterate.
                for key in resource.values():
                    if self._matches_user_id(key, user_id):
                        results.append(key)
        return results
