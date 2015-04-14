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

import abc
import collections
import datetime
import re

from Crypto import Random
from Crypto.Hash import SHA
from zope.interface import implementer
from zope.interface import provider

from pgp import s2k
from pgp.packets import constants as C
from pgp.packets import packets
from pgp.packets import parsers
from pgp.signature import BaseSignature
from pgp import utils


INCOMPLETE_CRLF = re.compile(b'(\r[^\n]|[^\r]\n)', re.M)


class MessageSignature(BaseSignature):

    one_pass = None


class BaseMessage(object):

    def sign(self, secret_key, signature_version=4,
             signature_type=C.SIGNATURE_OF_A_BINARY_DOCUMENT,
             hash_algorithm=None, one_pass=True):

        if hash_algorithm is None:
            hash_algorithms = secret_key.preferred_hash_algorithms
            if hash_algorithms:
                hash_algorithm = hash_algorithms[0]
            else:
                hash_algorithm = 1
        signature = secret_key.sign(self, signature_version, signature_type,
                                    hash_algorithm)
        return SignedMessageWrapper([signature], self, one_pass)

    def compress(self, compression_algorithm, compression_level):
        return CompressedMessageWrapper(compression_algorithm,
                                        compression_level, self)

    def public_key_encrypt(self, symmetric_algorithm, public_key=None,
                           public_keys=None, hidden_public_keys=None,
                           session_key=None, integrity_protect=True):
        if public_keys is not None and public_key is not None:
            raise TypeError(
                'Must be called with one of `public_key` or '
                '`public_keys`.')
        elif public_key is not None:
            public_keys = [public_key]
        if hidden_public_keys is None:
            hidden_public_keys = []
        if session_key is None:
            key_len = utils.symmetric_cipher_key_lengths[symmetric_algorithm]
            session_key = Random.new().read(key_len)
        session_key_objs = []
        for public_key in public_keys:
            session_key_objs.append(
                PublicKeySessionKey(3, public_key=public_key,
                                    symmetric_algorithm=symmetric_algorithm,
                                    session_key=session_key)
                )
        for public_key in hidden_public_keys:
            session_key_objs.append(
                PublicKeySessionKey(3, public_key=public_key,
                                    symmetric_algorithm=symmetric_algorithm,
                                    session_key=session_key,
                                    hide_key_id=True)
                )
        packet_data = b''.join(map(bytes, self.to_packets()))
        message_data_obj = SymmetricallyEncryptedMessageData(
            symmetric_algorithm, session_key, packet_data,
            integrity_protected=integrity_protect, version=1
            )
        return EncryptedMessageWrapper(session_key_objs, message_data_obj)

    def symmetric_encrypt(self, symmetric_algorithm, passphrase,
                          session_key=None, integrity_protect=True,
                          s2k_type=None, s2k_hash_algorithm=None,
                          s2k_symmetric_algorithm=None,
                          s2k_salt=None, s2k_count=None):
        if s2k_type is None:
            s2k_type = 3
        if s2k_symmetric_algorithm is None:
            s2k_symmetric_algorithm = symmetric_algorithm
        if s2k_hash_algorithm is None:
            s2k_hash_algorithm = 1
        if s2k_count is None:
            s2k_count = 65536
        if s2k_salt is None:
            s2k_salt = Random.new().read(8)
        if isinstance(passphrase, str):
            passphrase = passphrase.encode('utf8')
        S2KCls = s2k.S2K_TYPES[s2k_type]
        s2k_specification = S2KCls(
            symmetric_algorithm=s2k_symmetric_algorithm,
            hash_algorithm=s2k_hash_algorithm,
            salt=s2k_salt,
            count=s2k_count
            )
        if session_key is None:
            key_len = utils.symmetric_cipher_key_lengths[symmetric_algorithm]
            session_key = Random.new().read(key_len)
        session_key_obj = SymmetricSessionKey(
            symmetric_algorithm=symmetric_algorithm,
            s2k_specification=s2k_specification,
            passphrase=passphrase,
            session_key=session_key)
        packet_data = b''.join(map(bytes, self.to_packets()))
        message_data_obj = SymmetricallyEncryptedMessageData(
            symmetric_algorithm, session_key, packet_data,
            integrity_protected=integrity_protect, version=1
            )
        return EncryptedMessageWrapper([session_key_obj], message_data_obj)


# https://tools.ietf.org/html/rfc4880#section-11.3
class LiteralMessage(BaseMessage):
    # A literal data packet
    packet_header_type = C.NEW_PACKET_HEADER_TYPE

    @classmethod
    def from_packet(cls, packet):
        data_format = packet.data_format
        if data_format in (b'u', b't'):
            class_ = TextMessage
        else:
            class_ = BinaryMessage
        filename = packet.filename
        timestamp = datetime.datetime.fromtimestamp(packet.time)
        data = packet.data
        return class_(data, filename, timestamp)

    @abc.abstractmethod
    def __init__(self, data, filename, timestamp):
        self.data = data
        self.filename = filename
        self.timestamp = timestamp

    @abc.abstractmethod
    def to_packet(self, header_format=None):
        raise NotImplemented

    def to_packets(self, header_format=None):
        return [self.to_packet(header_format)]

    def to_signable_data(self, signature_type, signature_version=3):
        return self.data


class TextMessage(LiteralMessage):

    def to_packet(self, header_format=None):
        if header_format is None:
            header_format = self.packet_header_type
        return packets.LiteralDataPacket(
                    header_format, b'u', self.filename, self.timestamp,
                    self.data)

    def __init__(self, data, filename, timestamp):
        self.data = data
        self.filename = filename
        self.timestamp = timestamp

    def to_signable_data(self, signature_type, signature_version=3):
        data = self.data.encode('utf8')
        if signature_type == C.SIGNATURE_OF_A_CANONICAL_TEXT_DOCUMENT:
            return INCOMPLETE_CRLF.replace(b'\r\n', data)
        return data


class BinaryMessage(LiteralMessage):

    def to_packet(self, header_format=None):
        if header_format is None:
            header_format = self.packet_header_type
        return packets.LiteralDataPacket(
                    header_format, b'b', self.filename, self.timestamp,
                    self.data)

    def __init__(self, data, filename, timestamp):
        self.data = data
        self.filename = filename
        self.timestamp = timestamp


encrypted_message_data_packet_types = (
    # DATA
    C.SYMMETRICALLY_ENCRYPTED_DATA_PACKET_TYPE,
    C.SYMMETRICALLY_ENCRYPTED_AND_INTEGRITY_PROTECTED_DATA_PACKET_TYPE,
    )


encrypted_message_session_key_packet_types = (
    # ESK
    C.SYMMETRIC_KEY_ENCRYPTED_SESSION_KEY_PACKET_TYPE,
    C.PUBLIC_KEY_ENCRYPTED_SESSION_KEY_PACKET_TYPE,
    )


encrypted_message_packet_types = (
    encrypted_message_data_packet_types +
    encrypted_message_session_key_packet_types
    )


class EncryptedSessionKey(object, metaclass=abc.ABCMeta):

    @abc.abstractmethod
    def encrypt(self, passphrase, data):
        pass

    @abc.abstractmethod
    def decrypt(self, passphrase, data):
        pass


class SymmetricSessionKey(object):

    packet_header_type = C.NEW_PACKET_HEADER_TYPE
    symmetric_algorithm = None
    s2k_specification = None
    session_key = None

    @classmethod
    def from_packet(cls, packet):
        return cls(packet.symmetric_algorithm, packet.s2k_specification,
                   encrypted_key=packet.encrypted_session_key)

    def __init__(self, symmetric_algorithm, s2k_specification,
                 passphrase=None, session_key=None, encrypted_key=None):
        self.symmetric_algorithm = symmetric_algorithm
        self.s2k_specification = s2k_specification
        self.encrypted_key = encrypted_key
        if passphrase is not None:
            self.set_session_key(passphrase, session_key)

    def get_algorithm_and_session_key(self, passphrase):
        PacketCls = packets.SymmetricKeyEncryptedSessionKeyPacket
        if isinstance(passphrase, str):
            passphrase = passphrase.encode('utf8')

        return PacketCls._get_key_and_cipher_algo(
                    self.s2k_specification, self.symmetric_algorithm,
                    passphrase, self.encrypted_key)

    def set_session_key(self, passphrase, session_key=None):
        # "If the encrypted session key is not present (which can be detected
        #  on the basis of packet length and S2K specifier size), then the S2K
        #  algorithm applied to the passphrase produces the session key for
        #  decrypting the file, using the symmetric cipher algorithm from the
        #  Symmetric-Key Encrypted Session Key packet.
        #
        # "If the encrypted session key is present, the result of applying the
        #  S2K algorithm to the passphrase is used to decrypt just that
        #  encrypted session key field, using CFB mode with an IV of all zeros.
        #  The decryption result consists of a one-octet algorithm identifier
        #  that specifies the symmetric-key encryption algorithm used to
        #  encrypt the following Symmetrically Encrypted Data packet, followed
        #  by the session key octets themselves."
        if not session_key:
            self.encrypted_key = None
        else:
            PacketCls = packets.SymmetricKeyEncryptedSessionKeyPacket
            skey = self.s2k_specification.to_key(passphrase)
            self.encrypted_key = PacketCls._get_encrypted_key(
                self.s2k_specification, self.symmetric_algorithm, passphrase,
                session_key)

    def to_packet(self, header_format=None):
        if header_format is None:
            header_format = self.packet_header_type

        return packets.SymmetricKeyEncryptedSessionKeyPacket(
            header_format,
            4,  # "The only currently defined version is 4."
            self.symmetric_algorithm,
            self.s2k_specification,
            self.encrypted_key
            )


EncryptedSessionKey.register(SymmetricSessionKey)


class PublicKeySessionKey(object):

    packet_header_type = C.NEW_PACKET_HEADER_TYPE
    symmetric_algorithm = 1  # IDEA
    key_hash_algorithm = 1  # MD5

    @classmethod
    def from_packet(cls, packet):
        result = cls(
            packet.version,
            public_key_algorithm=packet.public_key_algorithm,
            key_id=packet.key_id,
            encrypted_key=packet.encrypted_session_key,
            )
        result.packet_header_type = packet.header_format
        return result

    def to_packet(self, header_format=None):
        if header_format is None:
            header_format = self.packet_header_type
        result = packets.PublicKeyEncryptedSessionKeyPacket(
            header_format,
            self.version,
            key_id=self.key_id,
            public_key_algorithm=self.public_key_algorithm,
            encrypted_session_key=self.encrypted_key,
            )
        return result

    def __init__(self, version, public_key=None, symmetric_algorithm=None,
                 session_key=None, public_key_algorithm=None, key_id=None,
                 encrypted_key=None, hide_key_id=False):
        self.version = version
        self.public_key_algorithm = public_key_algorithm
        self.key_id = key_id
        if public_key:
            self.public_key_algorithm = public_key.public_key_algorithm
            self.key_id = public_key.key_id
        if encrypted_key:
            self.encrypted_key = encrypted_key
        if session_key:
            self.set_algorithm_and_session_key(public_key,
                                               symmetric_algorithm,
                                               session_key)

    def get_algorithm_and_session_key(self, secret_key):
        if secret_key.is_locked():
            raise RuntimeError('Key must be unlocked.')
        ko = secret_key._get_key_obj()
        PktCls = packets.PublicKeyEncryptedSessionKeyPacket
        return \
            PktCls._get_key_and_cipher_algo(
                self.public_key_algorithm, ko, self.encrypted_key
            )

    def set_algorithm_and_session_key(self, public_key, sym_algorithm,
                                      session_key):
        ko = public_key._get_key_obj()
        PktCls = packets.PublicKeyEncryptedSessionKeyPacket
        self.encrypted_key = PktCls._get_encrypted_key(
            public_key.public_key_algorithm, ko, sym_algorithm, session_key
            )


EncryptedSessionKey.register(PublicKeySessionKey)


class DefaultSessionKey(object):

    symmetric_algorithm = 1  # IDEA
    key_hash_algorithm = 1  # MD5

    def get_algorithm_and_session_key(self, passphrase):
        hash_ = utils.get_hash_instance(self.key_hash_algorithm)
        hash_.update(passphrase)
        key = hash_.digest()
        return 1, key

    def set_algorithm_and_session_key(self, *args, **kwargs):
        raise TypeError()


EncryptedSessionKey.register(DefaultSessionKey)
SymEncAndIPDPacket = \
    packets.SymmetricallyEncryptedAndIntegrityProtectedDataPacket


class SymmetricallyEncryptedMessageData(object):
    packet_header_type = C.NEW_PACKET_HEADER_TYPE

    @classmethod
    def from_packet(cls, packet):
        integrity_protected = (
            packet.type ==
            C.SYMMETRICALLY_ENCRYPTED_AND_INTEGRITY_PROTECTED_DATA_PACKET_TYPE
            )
        version = None
        if integrity_protected:
            version = packet.version
        return cls(
            encrypted_data=packet.encrypted_data,
            integrity_protected=integrity_protected,
            version=version
            )

    def __init__(self, symmetric_algorithm=None, session_key=None, data=None,
                 encrypted_data=None, integrity_protected=False, version=None):
        self.data = encrypted_data
        self.integrity_protected = integrity_protected
        self.version = version
        if data:
            self.encrypt(symmetric_algorithm, session_key, data)

    def encrypt(self, symmetric_algo, key, message):
        block_len = utils.symmetric_cipher_block_lengths[symmetric_algo]
        iv = Random.new().read(block_len)
        data = bytearray()
        cipher = utils.get_symmetric_cipher(
            symmetric_algo,
            key,
            utils.CFB,
            b'\x00' * block_len
            )
        padding = 0
        offset = 0
        if not self.integrity_protected:
            padding = block_len - len(message) % block_len
            message = message + b'\x00' * padding
            data.extend(cipher.encrypt(iv + iv[-2:]))
            cipher = utils.get_symmetric_cipher(
                symmetric_algo,
                key,
                utils.CFB,
                iv
                )
            data.extend(cipher.encrypt(message))
        else:
            padding = block_len - (len(message) + 2 + 22) % block_len
            data.extend(cipher.encrypt(iv))
            hash_ = SHA.new(iv)
            hash_.update(iv[-2:])
            message = message + b'\xd3\x14'
            hash_.update(message)
            mdc = hash_.digest()
            message = message + mdc + (b'\x00' * padding)
            data.extend(cipher.encrypt(iv[-2:] + message)[:-padding])

        self.data = data

    def decrypt(self, symmetric_algo, key):
        encrypted_data = bytes(self.data)
        decrypted_data = bytearray()
        offset = 0
        padding = 0
        block_len = utils.symmetric_cipher_block_lengths[symmetric_algo]
        encrypted_iv = encrypted_data[:block_len + 2]
        cipher = utils.get_symmetric_cipher(
            symmetric_algo,
            key,
            utils.CFB,
            b'\x00' * block_len)
        decrypted_iv = cipher.decrypt(encrypted_data[:block_len])
        if self.integrity_protected:
            # "Unlike the Symmetrically Encrypted Data Packet, no special CFB
            #  resynchronization is done after encrypting this prefix data."
            offset += block_len
            first_block = cipher.decrypt(
                encrypted_data[offset:offset + block_len])
            offset += block_len
            iv_check = first_block[:2]
            if iv_check != decrypted_iv[-2:]:
                raise ValueError()

            decrypted_data.extend(first_block[2:])

            # Pad the remaining data manually
            padding = block_len - (len(encrypted_data) - offset) % block_len
            encrypted_data += b'\x00' * padding
        else:
            cipher = utils.get_symmetric_cipher(
                symmetric_algo,
                key,
                utils.OPENPGP,
                encrypted_iv)

        decrypted_data.extend(cipher.decrypt(encrypted_data[offset:]))
        decrypted_data = decrypted_data[:-padding]
        # We run into trouble here with partial body lengths and the MDC.
        # Let's make pretend.
        mdc_data = bytearray()
        main_data = decrypted_data
        if decrypted_data[-22:-20] == b'\xd3\x14':
            # It's there. Hold it back.
            mdc_data = decrypted_data[-22:]
            main_data = decrypted_data[:-22]
        data_len = len(main_data)
        offset = 0
        decrypted_packets = []
        while offset < data_len:
            offset, packet = packets.packet_from_packet_data(main_data, offset)
            decrypted_packets.append(packet)

        if mdc_data:
            # One more for the MDC
            offset, packet = packets.packet_from_packet_data(mdc_data, 0)
            decrypted_packets.append(packet)

        if self.integrity_protected:
            if (decrypted_packets[-1].type !=
                    C.MODIFICATION_DETECTION_CODE_PACKET_TYPE):
                raise ValueError(
                    'Integrity protected message is missing modification '
                    'detection code.')
            mdc = decrypted_packets.pop()
            hash_ = SHA.new(decrypted_iv)
            hash_.update(decrypted_iv[-2:])
            hash_.update(decrypted_data[:-20])
            if mdc.data != hash_.digest():
                raise ValueError(
                    'Integrity protected message does not match modification '
                    'detection code.')

        return open_pgp_message_from_packets(decrypted_packets)

    def to_packet(self, header_format=None):
        if header_format is None:
            header_format = self.packet_header_type
        if self.integrity_protected:
            return SymEncAndIPDPacket(
                header_format,
                self.version,
                self.data
                )
        else:
            return packets.SymmetricallyEncryptedDataPacket(
                header_format,
                self.data
                )

    def to_packets(self, header_format=None):
        return [self.to_packet(header_format)]


def parse_encrypted_message_packet(packet):
    return SymmetricallyEncryptedMessageData.from_packet(packet)


def parse_session_key_packet(packet):
    if packet.type == C.PUBLIC_KEY_ENCRYPTED_SESSION_KEY_PACKET_TYPE:
        return PublicKeySessionKey.from_packet(packet)
    elif packet.type == C.SYMMETRIC_KEY_ENCRYPTED_SESSION_KEY_PACKET_TYPE:
        return SymmetricSessionKey.from_packet(packet)
    else:
        raise TypeError(packet)


class EncryptedMessageWrapper(BaseMessage):

    @classmethod
    def from_packets(cls, packets):
        session_keys = []
        packet = packets.popleft()
        messages = []
        if packet.type in encrypted_message_data_packet_types:
            # No session key
            session_keys = [DefaultSessionKey()]
        while packet.type in encrypted_message_session_key_packet_types:
            session_keys.append(parse_session_key_packet(packet))
            if not packets:
                break
            packet = packets.popleft()

        if not session_keys:
            raise ValueError

        if packet.type in encrypted_message_packet_types:
            return cls(session_keys, parse_encrypted_message_packet(packet))

        raise TypeError

    def __init__(self, session_keys, message_data_obj):
        self.session_keys = session_keys
        self.message_data_obj = message_data_obj

    def get_message(self, secret_key_or_passphrase=None):
        # "In addition, decrypting a Symmetrically Encrypted Data packet or a
        #  Symmetrically Encrypted Integrity Protected Data packet as well as
        #  decompressing a Compressed Data packet must yield a valid OpenPGP
        #  Message."
        sym_algo = None
        sess_key = None
        for sess_key_obj in self.session_keys:
            if isinstance(sess_key_obj, PublicKeySessionKey):
                try:
                    sym_algo, sess_key = \
                        sess_key_obj.get_algorithm_and_session_key(
                            secret_key_or_passphrase)
                except ValueError:
                    continue
            elif isinstance(sess_key_obj, SymmetricSessionKey):
                sym_algo, sess_key = \
                    sess_key_obj.get_algorithm_and_session_key(
                        secret_key_or_passphrase)
            elif isinstance(sess_key_obj, DefaultSessionKey):
                sym_algo, sess_key = \
                    sess_key_obj.get_algorithm_and_session_key(
                        secret_key_or_passphrase)
            else:
                # TODO: consider raising an error
                continue
            return self.message_data_obj.decrypt(sym_algo, sess_key)

        # TODO: raise a better error
        raise ValueError()

    def to_packets(self, header_format=None):
        packets = []
        for k in self.session_keys:
            p = k.to_packet(header_format)
            if p is not None:
                packets.append(p)
        packets.extend(self.message_data_obj.to_packets(header_format))
        return packets


def parse_signature_from_packet(packet, message, one_pass=False):
    result = MessageSignature.from_packet(packet, message)
    result.one_pass = one_pass
    return result


class SignedMessageWrapper(BaseMessage):
    # A signature packet followed by any other message type, or a
    # one-pass signature packet followed by a message type, followed by a
    # matching signature packet

    @classmethod
    def from_packets(cls, packets):
        one_pass = False
        signatures = []
        message = None
        for packet in packets:
            if packet.type == C.ONE_PASS_SIGNATURE_PACKET_TYPE:
                one_pass = True
            elif packet.type == C.SIGNATURE_PACKET_TYPE:
                if message:
                    signature = parse_signature_from_packet(packet, message,
                                                            one_pass=one_pass)
                    signatures.append(signature)
                else:
                    raise TypeError()
            elif message is None:
                message = open_pgp_message_from_packets([packet])
            else:
                raise TypeError()
        return cls(signatures, message, one_pass)

    def __init__(self, signatures, message, one_pass=True):
        self.signatures = signatures
        self.message = message
        self.one_pass = one_pass

    def get_message(self):
        return self.message

    def to_packets(self, header_format=None):
        pkts = []
        op_header_format = header_format
        if self.one_pass:
            i = 0
            for sig in self.signatures:
                i += 1
                if not header_format:
                    op_header_format = sig.packet_header_type
                pkts.append(
                    packets.OnePassSignaturePacket(
                        op_header_format,
                        3,  # "The current version is 3."
                        sig.signature_type,
                        sig.hash_algorithm,
                        sig.public_key_algorithm,
                        sig.issuer_key_ids[0],
                        nested=(i != len(self.signatures))
                    ))
        pkts.extend(self.message.to_packets(header_format))
        for sig in self.signatures:
            pkts.append(sig.to_packet(header_format))
        return pkts


class CompressedMessageWrapper(BaseMessage):
    # A compressed data packet
    packet_header_type = C.NEW_PACKET_HEADER_TYPE

    @classmethod
    def from_packet(cls, packet):
        return cls(packet.compression_algorithm,
                   compressed_data=packet.compressed_data)

    def __init__(self, compression_algorithm, compression_level=None,
                 message=None, compressed_data=None):
        self.compression_algorithm = compression_algorithm
        self.compression_level = compression_level
        if compressed_data is not None:
            self.data = compressed_data
        if message is not None:
            self.set_message(message)

    def get_message(self):
        pkts = packets.CompressedDataPacket.decompress_data(
            self.compression_algorithm, self.data)
        return open_pgp_message_from_packets(pkts)

    def set_message(self, message):
        pkts = message.to_packets()
        self.data = packets.CompressedDataPacket.compress_packets(
            self.compression_algorithm, self.compression_level, pkts)

    def to_packet(self, header_format=None):
        if header_format is None:
            header_format = self.packet_header_type
        return packets.CompressedDataPacket(
                header_format, self.compression_algorithm, self.data)

    def to_packets(self, header_format=None):
        return [self.to_packet(header_format)]


def open_pgp_message_from_packets(pkts):
    pkts = collections.deque(pkts)
    packet = pkts.popleft()
    if packet.type in encrypted_message_packet_types:
        pkts.appendleft(packet)
        result = EncryptedMessageWrapper.from_packets(pkts)
    elif packet.type in (C.ONE_PASS_SIGNATURE_PACKET_TYPE,
                         C.SIGNATURE_PACKET_TYPE):
        pkts.appendleft(packet)
        result = SignedMessageWrapper.from_packets(pkts)
    elif packet.type == C.COMPRESSED_DATA_PACKET_TYPE:
        result = CompressedMessageWrapper.from_packet(packet)
    elif packet.type == C.LITERAL_DATA_PACKET_TYPE:
        result = LiteralMessage.from_packet(packet)

    return result


# https://tools.ietf.org/html/rfc4880#section-11.4
class DetachedSignature(object):
    # A single signature packet

    @classmethod
    def from_packets(cls, packets):
        pass

    def __init__(self, message):
        self.message = message

    def to_packets(self):
        pass
