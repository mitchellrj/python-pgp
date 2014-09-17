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
import email.utils
import math
import time
import weakref

from Crypto.Hash import SHA
import magic
from zope.interface import implementer
from zope.interface import provider

from pgp import interfaces
from pgp import exceptions
from pgp.packets import constants as C
from pgp.packets import packets
from pgp.packets import signature_subpackets
from pgp.packets import user_attribute_subpackets
from pgp.signature import BaseSignature
from pgp.user_id import parse_user_id
from pgp import utils


try:
    long
except NameError:
    long = int


class SignedMixin(object):

    @property
    def self_signatures(self):
        result = []
        for s in self.signatures:
            pk = self.primary_public_key or self
            key_ids = set([pk.key_id])
            key_ids |= set([
                subkey.key_id for subkey in
                pk.subkeys
                ])
            if key_ids & set(s.issuer_key_ids):
                # is selfsig
                result.append(s)
        return result

    @property
    def current_self_signatures(self):
        result = []
        for s in self.self_signatures:
            if (
                    s.signature_type in self._self_sig_types
                    and not s.revoked
                    and not s.expired
                    and not s.issuer_key_expired
                    and not s.issuer_key_revoked
                    ):
                result.append(s)
        return result

    @property
    def revocation_signatures(self):
        result = []
        for s in self.self_signatures:
            if (
                    s.signature_type in self._revocation_sig_types
                    and not s.revoked
                    and not s.expired
                    and not s.issuer_key_expired
                    and not s.issuer_key_revoked
                    ):
                result.append(s)
        return result

    @property
    def revoked(self):
        return bool(self.revocation_signatures)


    def get_most_recent_selfsig(self, revocation=False):
        last_signature_created = datetime.datetime(1900, 1, 1)
        most_recent_selfsig = None
        for signature in self.signatures:
            if not signature.is_self_signature():
                continue
            if not revocation and signature.signature_type not in self._self_sig_types:
                continue
            if revocation and signature.signature_type not in self._revocation_sig_types:
                continue
            if last_signature_created < signature.creation_time:
                most_recent_selfsig = signature

        return most_recent_selfsig

    @staticmethod
    def __selfsig_attribute(name, default=None, revocation=False):
        def getter(self):
            if self.version >= 4:
                most_recent_selfsig = self.get_most_recent_selfsig(revocation)
                result = getattr(most_recent_selfsig, name, default)

            return result

        def setter(self, value):
            if self.version >= 4:
                most_recent_selfsig = self.get_most_recent_selfsig(revocation)
                setattr(most_recent_selfsig, name, value)

        return property(getter, setter)

    __selfsig_attribute = __selfsig_attribute.__func__

    revocation_reason = __selfsig_attribute('revocation_reason', revocation=True)
    revocation_code = __selfsig_attribute('revocation_code', revocation=True)
    # Overridden in keys
    creation_time = __selfsig_attribute('creation_time')
    expiration_time = __selfsig_attribute('key_expiration_time')
    preferred_compression_algorithms = \
        __selfsig_attribute('preferred_compression_algorithms', [])
    preferred_hash_algorithms = \
        __selfsig_attribute('preferred_hash_algorithms', [])
    preferred_symmetric_algorithms = \
        __selfsig_attribute('preferred_symmetric_algorithms', [])
    revocation_keys = \
        __selfsig_attribute('revocation_keys', [])
    key_server_should_not_modify = \
        __selfsig_attribute('key_server_should_not_modify')
    preferred_key_server = __selfsig_attribute('preferred_key_server')
    primary_user_id = __selfsig_attribute('primary_user_id')
    policy_uri = __selfsig_attribute('policy_uri')
    may_certify_others = __selfsig_attribute('may_certify_others')
    may_sign_data = __selfsig_attribute('may_sign_data')
    may_encrypt_comms = __selfsig_attribute('may_encrypt_comms')
    may_encrypt_storage = __selfsig_attribute('may_encrypt_comms')
    may_be_used_for_auth = __selfsig_attribute('may_encrypt_comms')
    may_have_been_split = __selfsig_attribute('may_have_been_split')
    may_have_multiple_owners = \
        __selfsig_attribute('may_have_multiple_owners')
    supports_modification_detection = \
        __selfsig_attribute('may_have_multiple_owners')

    del __selfsig_attribute


class KeySignature(BaseSignature):

    def is_self_signature(self):
        parent = self.parent
        own_key_ids = []
        if isinstance(parent, (TransferablePublicKey, TransferableSecretKey)):
            primary_public_key = parent
        else:
            primary_public_key = parent.primary_public_key

        own_key_ids.append(primary_public_key.key_id)
        for subkey in primary_public_key.subkeys:
            own_key_ids.append(subkey.key_id)

        return bool(set(self.issuer_key_ids) & set(own_key_ids))


@implementer(interfaces.IPublicKey)
class BasePublicKey(SignedMixin):

    _self_sig_types = (C.SIGNATURE_DIRECTLY_ON_A_KEY,)
    _revocation_sig_types = (C.KEY_REVOCATION_SIGNATURE,)
    _PacketClass = packets.PublicKeyPacket
    packet_header_type = C.NEW_PACKET_HEADER_TYPE
    primary_public_key = None

    @classmethod
    def _init_args_from_packet(cls, packet):
        version = packet.version
        creation_time = datetime.datetime.fromtimestamp(packet.creation_time)
        public_key_algorithm = packet.public_key_algorithm
        expiration_days = packet.expiration_days
        if version < 4 or expiration_days in (None, 0):
            expiration_time = None
        else:
            expiration_time = \
                creation_time + datetime.timedelta(days=expiration_days)
        modulus_n = packet.modulus
        exponent_e = packet.exponent
        prime_p = packet.prime
        group_generator_g = packet.group_generator
        group_order_q = packet.group_order
        key_value_y = packet.key_value
        signatures = []
        return (version, public_key_algorithm, creation_time,
                expiration_time, modulus_n, exponent_e,
                prime_p, group_generator_g, group_order_q,
                key_value_y, signatures)

    @classmethod
    def from_packet(cls, packet):
        args = cls._init_args_from_packet(packet)
        result = cls(*args)
        result.packet_header_type = packet.header_format
        return result

    def _to_packet_args(self, header_format=None):
        creation_time = int(time.mktime(self.creation_time.timetuple()))
        expiration_days = None
        if self.version < 4:
            expiration_time = self.expiration_time
            if expiration_time is not None:
                expiration_days = (expiration_time - creation_time).days

        return (
            header_format, self.version, creation_time,
            self.public_key_algorithm, expiration_days, self.modulus_n,
            self.exponent_e, self.prime_p, self.group_order_q,
            self.group_generator_g, self.key_value_y
            )

    def to_packet(self, header_format=None):
        if header_format is None:
            header_format = self.packet_header_type
        args = self._to_packet_args(header_format)
        return self._PacketClass(*args)

    def to_signable_data(self, signature_type, signature_version=3):
        key_packet_data = self.to_packet().content
        key_length = len(key_packet_data)
        result = bytearray([0x99])
        result.extend(utils.int_to_2byte(key_length))
        result.extend(key_packet_data)
        return result

    def encrypt(self, message):
        raise NotImplemented

    signatures = None
    version = None
    public_key_algorithm = None
    modulus_n = None
    exponent_e = None
    prime_p = None
    group_generator_g = None
    group_order_q = None
    key_value_y = None
    creation_time = None
    _expiration_time = None

    def __init__(self, version, public_key_algorithm, creation_time,
                 expiration_time=None, modulus_n=None, exponent_e=None,
                 prime_p=None, group_generator_g=None, group_order_q=None,
                 key_value_y=None, signatures=None):
        if signatures is None:
            signatures = []
        self.signatures = signatures
        self.version = version
        self.public_key_algorithm = public_key_algorithm
        self.modulus_n = modulus_n
        self.exponent_e = exponent_e
        self.prime_p = prime_p
        self.group_generator_g = group_generator_g
        self.group_order_q = group_order_q
        self.key_value_y = key_value_y
        self.creation_time = creation_time
        self._expiration_time = expiration_time

    def __repr__(self):
        return '<{0} 0x{1}>'.format(self.__class__.__name__,
                                    self.key_id)

    def _get_expiration_time(self):
        if self.version in (2, 3):
            return self._expiration_time
        elif self.version >= 4:
            return super(BasePublicKey, self).expiration_time

    def _set_expiration_time(self, value):
        if self.version in (2, 3):
            self._expiration_time = value
        elif self.version >= 4:
            super(BasePublicKey, self).expiration_time = value

    expiration_time = property(_get_expiration_time, _set_expiration_time)

    @property
    def _public_key_obj(self):
        key_obj = None
        K = utils.get_public_key_constructor(self.public_key_algorithm)
        if self.public_key_algorithm in (1, 2, 3):
            key_obj = K((self.modulus_n, self.exponent_e))
        elif self.public_key_algorithm in (16, 20):
            key_obj = K((self.prime_p, self.group_generator_g,
                         self.key_value_y))
        elif self.public_key_algorithm == 17:
            key_obj = K((self.prime_p, self.group_order_q,
                         self.group_generator_g, self.key_value_y))
        return key_obj

    @property
    def bit_length(self):
        if self.public_key_algorithm in (1, 2, 3):
            n = self.modulus_n
        elif self.public_key_algorithm == 17:
            n = self.prime_p
        elif self.public_key_algorithm in (16, 20):
            n = self.prime_p

        return int(math.ceil(float(math.log(n, 2))))

    @property
    def key_id(self):
        if self.version < 4:
            n = None
            if self.public_key_algorithm in (1, 2, 3):
                n = self.modulus_n
            elif self.public_key_algorithm in (16, 17, 20):
                n = self.prime_p
            return utils.int_to_hex(n, 16)
        else:
            return self.fingerprint[-16:]

    @property
    def fingerprint(self):
        return utils.key_packet_fingerprint(self.to_packet())

    @property
    def keygrip(self):
        sexp = ''
        if self.public_key_algorithm in (1, 2, 3):
            sexp = '(public-key(rsa(n{n})(e{e})))'.format(
                    n=self.modulus_n, e=self.exponent_e)
        elif self.public_key_algorithm == 17:
            sexp = '(public-key(dsa(p{p})(q{q})(g{g})(y{y})))'.format(
                    p=self.prime_p, q=self.group_order_q,
                    g=self.group_generator_g, y=self.key_value_y)
        elif self.public_key_algorithm in (16, 20):
            sexp = '(public-key(elg(p{p})(g{g})(y{y})))'.format(
                    p=self.prime_p, g=self.group_generator_g,
                    y=self.key_value_y)
        else:
            raise ValueError

        return SHA.new(sexp.encode('us-ascii')).hexdigest().upper()

    def _get_key_obj(self):
        key_constructor = utils.get_public_key_constructor(self.public_key_algorithm)

        if self.public_key_algorithm == 17:
            key_obj = key_constructor((long(self.key_value_y),
                                       long(self.group_generator_g),
                                       long(self.prime_p),
                                       long(self.group_order_q)
                                       ))
        elif self.public_key_algorithm == 20:
            key_obj = key_constructor((long(self.prime_p),
                                       long(self.group_generator_g),
                                       long(self.key_value_y)
                                       ))
        elif self.public_key_algorithm in (1, 3):
            key_obj = key_constructor((long(self.modulus_n),
                                       long(self.exponent_e)
                                       ))
        else:
            raise UnsupportedPublicKeyAlgorithm(algorithm_type)

        return key_obj

    def verify(self, signature, item):
        if self.key_id not in signature.issuer_key_ids:
            raise exceptions.SignatureVerificationFailed('Signature not made by this key.')

        if self.public_key_algorithm != signature.public_key_algorithm:
            raise exceptions.SignatureVerificationFailed('Signature not made by this key.')

        signature_values = signature.signature_values

        key_obj = self._get_key_obj()
        hash_ = utils.get_hash_instance(signature.hash_algorithm)
        hash_.update(item.to_signable_data(signature.signature_type,
                                           signature.version))
        hash_.update(signature.to_signable_data(signature.signature_type,
                                                signature.version))
        if hash_.digest()[:2] != signature.hash2:
            raise exceptions.SignatureVerificationFailed()

        if not utils.verify_hash(signature.public_key_algorithm, key_obj,
                                 hash_, signature_values):
            raise exceptions.SignatureVerificationFailed()

        return True


class BaseSecretKey(BasePublicKey):

    s2k_specification = None
    symmetric_algorithm = None
    iv = None
    encrypted_portion = None
    checksum = None
    hash = None
    _locked = True

    # RSA
    exponent_d = None
    prime_p = None
    prime_q = None
    multiplicative_inverse_u = None

    # DSA / Elg
    exponent_x = None

    @classmethod
    def _init_args_from_packet(cls, packet):
        args = BasePublicKey._init_args_from_packet(packet)
        args += (packet.s2k_specification, packet.symmetric_algorithm,
                 packet.iv, packet.encrypted_portion, packet.checksum,
                 packet.hash)
        return args

    def __init__(self, version, public_key_algorithm, creation_time,
                 expiration_time=None, modulus_n=None, exponent_e=None,
                 prime_p=None, group_generator_g=None, group_order_q=None,
                 key_value_y=None, signatures=None, s2k_specification=None,
                 symmetric_algorithm=None, iv=None, encrypted_portion=None,
                 checksum=None, hash_=None):
        BasePublicKey.__init__(self, version, public_key_algorithm,
                               creation_time, expiration_time, modulus_n,
                               exponent_e, prime_p, group_generator_g,
                               group_order_q, key_value_y, signatures)
        self.s2k_specification = s2k_specification
        self.symmetric_algorithm = symmetric_algorithm
        self.iv = iv
        self.encrypted_portion = encrypted_portion
        self.checksum = checksum
        self.hash = hash_

    def to_signable_data(self, signature_type, signature_version=3):
        return self.to_public_key().to_signable_data(signature_type,
                                                     signature_version)

    def to_public_key(self):
        key = self._PublicClass(
            self.version, self.public_key_algorithm, self.creation_time,
            self.expiration_time, self.modulus_n, self.exponent_e,
            self.prime_p, self.group_generator_g, self.group_order_q,
            self.key_value_y, self.signatures)
        key.packet_header_type = self.packet_header_type
        return key

    def _to_packet_args(self, header_format=None):
        args = BasePublicKey._to_packet_args(self, header_format)
        args += (self.s2k_specification, self.symmetric_algorithm, self.iv,
                 self.encrypted_portion, self.checksum, self.hash)
        return args

    def _get_key_obj(self):
        key_constructor = utils.get_public_key_constructor(self.public_key_algorithm)
        if self.is_locked():
            return super(BaseSecretKey, self)._get_key_obj()

        if self.public_key_algorithm == 17:
            key_obj = key_constructor((long(self.key_value_y),
                                       long(self.group_generator_g),
                                       long(self.prime_p),
                                       long(self.group_order_q),
                                       long(self.exponent_x)
                                       ))
        elif self.public_key_algorithm == 20:
            key_obj = key_constructor((long(self.prime_p),
                                       long(self.group_generator_g),
                                       long(self.key_value_y),
                                       long(self.exponent_x)
                                       ))
        elif self.public_key_algorithm in (1, 3):
            key_obj = key_constructor((long(self.modulus_n),
                                       long(self.exponent_e),
                                       long(self.exponent_d),
                                       long(self.prime_p),
                                       long(self.prime_q),
                                       long(self.multiplicative_inverse_u)
                                       ))
        else:
            raise UnsupportedPublicKeyAlgorithm(algorithm_type)

        return key_obj

    def decrypt(self, message):
        if self.is_locked():
            raise RuntimeError('Secret key must be unlocked before decrypting.')

    def sign(self, item, version, signature_type, hash_algorithm,
             hashed_subpackets=None):
        if self.is_locked():
            raise RuntimeError('Secret key must be unlocked before signing.')

        key_obj = self._get_key_obj()

        hash_ = utils.get_hash_instance(hash_algorithm)
        hash_.update(item.to_signable_data(signature_type, version))
        if isinstance(item, (BasePublicKey, UserID, UserAttribute)):
            SigClass = KeySignature
        else:
            SigClass = BaseSignature
        creation_time = int(time.time())
        issuer_key_id = self.key_id
        hashed_subpackets = hashed_subpackets or []
        unhashed_subpackets = []
        creation_time_arg = None
        issuer_key_id_arg = None
        if version in (2, 3):
            creation_time_arg = creation_time
            issuer_key_id_arg = issuer_key_id
        elif version == 4:
            creation_time_subpacket = signature_subpackets.CreationTimeSubpacket(
                False, creation_time)
            issuer_subpacket = signature_subpackets.IssuerSubpacket(
                False, issuer_key_id)
            hashed_subpackets.insert(0, creation_time_subpacket)
            hashed_subpackets.insert(0, issuer_subpacket)

        sig = SigClass(item, version, signature_type,
                       self.public_key_algorithm, hash_algorithm, hash2=b'',
                       signature_values=(), creation_time=creation_time_arg,
                       issuer_key_id=issuer_key_id_arg,
                       hashed_subpackets=hashed_subpackets,
                       unhashed_subpackets=unhashed_subpackets
                       )
        hash_.update(sig.to_signable_data(signature_type, version))
        hash2 = bytearray(hash_.digest()[:2])
        sig.hash2 = hash2

        signature_values = utils.sign_hash(self.public_key_algorithm, key_obj,
                                           hash_)
        sig.signature_values = signature_values

        return sig

    def unlock(self, passphrase):
        if self.s2k_specification is not None:
            # TODO: Check encoding
            key = self.s2k_specification.to_key(passphrase.encode('utf8'))
        else:
            key = passphrase

        values = packets.SecretKeyPacket.decrypt_encrypted_key_portion(
                    self.version, key, self.symmetric_algorithm, self.iv,
                    self.encrypted_portion, self.checksum, self.hash)

        if self.public_key_algorithm in (1, 2, 3):
            # RSA
            self.exponent_d = values[0]
            self.prime_p = values[1]
            self.prime_q = values[2]
            self.multiplicative_inverse_u = values[3]
        elif self.public_key_algorithm in (16, 17, 20):
            # DSA & Elg
            self.exponent_x = values[0]
        else:
            raise ValueError

        self._locked = False
        return

    def lock(self):
        if self.public_key_algorithm in (1, 2, 3):
            # RSA
            self.exponent_d = None
            self.prime_p = None
            self.prime_q = None
            self.multiplicative_inverse_u = None
        elif self.public_key_algorithm in (16, 17, 20):
            # DSA & Elg
            self.exponent_x = None
        else:
            raise ValueError

        self._locked = True
        return

    def is_locked(self):
        return self._locked


class PublicSubkey(BasePublicKey):

    _self_sig_types = (C.SUBKEY_BINDING_SIGNATURE,)
    _revocation_sig_types = (C.SUBKEY_REVOCATION_SIGNATURE,)
    _PacketClass = packets.PublicSubkeyPacket

    @classmethod
    def from_packet(cls, primary_public_key, packet):
        args = cls._init_args_from_packet(packet)
        result = cls(primary_public_key, *args)
        result.packet_header_type = packet.header_format
        return result

    def __init__(self, primary_public_key, *args, **kwargs):
        self._primary_public_key_ref = weakref.ref(primary_public_key)
        BasePublicKey.__init__(self, *args, **kwargs)

    def to_signable_data(self, signature_type, signature_version=3):
        result = self.primary_public_key.to_signable_data(signature_type,
                                                          signature_version)
        result.extend(super(PublicSubkey, self).to_signable_data(signature_type,
                                                                 signature_version))
        return result

    @property
    def primary_public_key(self):
        return self._primary_public_key_ref()


class SecretSubkey(PublicSubkey, BaseSecretKey):

    _PacketClass = packets.SecretSubkeyPacket
    _PublicClass = PublicSubkey

    def __init__(self, primary_public_key, *args, **kwargs):
        self._primary_public_key_ref = weakref.ref(primary_public_key)
        BaseSecretKey.__init__(self, *args, **kwargs)

    def to_public_key(self):
        key = self._PublicClass(
            self.primary_public_key, self.version, self.public_key_algorithm,
            self.creation_time, self.expiration_time, self.modulus_n,
            self.exponent_e, self.prime_p, self.group_generator_g,
            self.group_order_q, self.key_value_y, self.signatures)
        key.packet_header_type = self.packet_header_type
        return key


@implementer(interfaces.IUserID)
class UserID(SignedMixin):

    signatures = None
    packet_header_type = C.NEW_PACKET_HEADER_TYPE
    _self_sig_types = (C.GENERIC_CERTIFICATION,
                       C.CASUAL_CERTIFICATION,
                       C.PERSONA_CERTIFICATION,
                       C.POSITIVE_CERTIFICATION)
    _revocation_sig_types = (C.CERTIFICATION_REVOCATION_SIGNATURE,)
    version = 4

    @classmethod
    def from_packet(cls, primary_public_key, packet):
        result = cls(primary_public_key, packet.user_id, [])
        result.packet_header_type = packet.header_format
        return result

    def to_packet(self, header_format=None):
        if header_format is None:
            header_format = self.packet_header_type
        return packets.UserIDPacket(header_format, self.user_id)

    def to_signable_data(self, signature_type, signature_version=3):
        result = self.primary_public_key.to_signable_data(signature_type,
                                                          signature_version)
        target_packet_data = self.to_packet().content
        if signature_version >= 4:
            result.append(0xb4)
            result.extend(utils.int_to_4byte(len(target_packet_data)))
        result.extend(target_packet_data)
        return result

    def __init__(self, primary_public_key, user_id, signatures=None):
        if signatures is None:
            signatures = []
        self._primary_public_key_ref = weakref.ref(primary_public_key)
        self.user_id = user_id
        self.signatures = signatures

    def __repr__(self):
        return '<{0} {1}>'.format(self.__class__.__name__,
                                 repr(self.user_id))

    @property
    def primary_public_key(self):
        return self._primary_public_key_ref()

    def _make_user_id(self, name, email, comment):
        result = email.utils.formataddr((name, email), 'utf8')
        if comment:
            result = u"{0} ({1})".format(result, comment)
        return result

    def _get_user_name(self):
        return parse_user_id(self.user_id)[0]

    def _set_user_name(self, name):
        self.user_id = self._make_user_id(name, self.user_email,
                                          self.user_comment)

    user_name = property(_get_user_name, _set_user_name)

    def _get_user_email(self):
        return parse_user_id(self.user_id)[1]

    def _set_user_email(self, email):
        self.user_id = self._make_user_id(self.user_name, email,
                                          self.user_comment)

    user_email = property(_get_user_email, _set_user_email)

    def _get_user_comment(self):
        return parse_user_id(self.user_id)[2]

    def _set_user_comment(self, comment):
        self.user_id = self._make_user_id(self.user_name, self.user_email,
                                          comment)

    user_comment = property(_get_user_comment, _set_user_comment)


@implementer(interfaces.IUserAttributeContentItem)
class UserAttributeContentItem(object):

    mime_type = None
    data = None

    @classmethod
    def from_subpacket(cls, subpacket):
        if subpacket.image_format == C.JPEG_IMAGE_FORMAT:
            mime_type = 'image/jpeg'
        else:
            mime_type = magic.from_buffer(subpacket.data[:1024],
                                          mime=True).decode('ascii')
        return cls(mime_type, subpacket.data)

    def __init__(self, mime_type, data):
        self.mime_type = mime_type
        self.data = data

    def __repr__(self):
        return '<{0} at 0x{2:x}>'.format(self.__class__.__name__, id(self))

    def to_subpacket(self):
        if self.mime_type.split('/', 1)[0] != 'image':
            return None
        header_version = 1
        if self.mime_type.endswith('/jpeg'):
            image_format = C.JPEG_IMAGE_FORMAT
        else:
            image_format = 101

        return user_attribute_subpackets.ImageAttributeSubpacket(
                    header_version, 16, image_format, self.data
                )


@implementer(interfaces.IUserAttribute)
class UserAttribute(SignedMixin):

    content_items = None
    signatures = None
    packet_header_type = C.NEW_PACKET_HEADER_TYPE
    _self_sig_types = (C.GENERIC_CERTIFICATION,
                       C.CASUAL_CERTIFICATION,
                       C.PERSONA_CERTIFICATION,
                       C.POSITIVE_CERTIFICATION)
    _revocation_sig_types = (C.CERTIFICATION_REVOCATION_SIGNATURE,)
    version = 4

    @classmethod
    def from_packet(cls, primary_public_key, packet):
        content_items = []
        for sp in packet.subpackets:
            content_items.append(UserAttributeContentItem.from_subpacket(sp))
        result = cls(primary_public_key, content_items)
        result.packet_header_type = packet.header_format
        return result

    def to_packet(self, header_format=None):
        subpackets = []
        if header_format is None:
            header_format = self.packet_header_type
        for item in self.content_items:
            subpackets.append(item.to_subpacket())
        return packets.UserAttributePacket(header_format, subpackets)

    def to_signable_data(self, signature_type, signature_version=3):
        result = self.primary_public_key.to_signable_data(signature_type,
                                                          signature_version)
        target_packet_data = self.to_packet().content
        if signature_version >= 4:
            result.append(0xd1)
            result.extend(utils.int_to_4byte(len(target_packet_data)))
        result.extend(target_packet_data)
        return result

    def __init__(self, primary_public_key, content_items, signatures=None):
        if signatures is None:
            signatures = []
        self._primary_public_key_ref = weakref.ref(primary_public_key)
        self.content_items = content_items
        self.signatures = signatures

    @property
    def primary_public_key(self):
        return self._primary_public_key_ref()

    def is_primary_user_attribute(self):
        pass


def validate_transferrable_key(packets, secret=False):
    # http://tools.ietf.org/html/rfc4880#section-11.1

    type_order = list(map(lambda p: p.type, packets))
    previous = None
    if not secret:
        key_packet_type = C.PUBLIC_KEY_PACKET_TYPE
        subkey_packet_type = C.PUBLIC_SUBKEY_PACKET_TYPE
    else:
        key_packet_type = C.SECRET_KEY_PACKET_TYPE
        subkey_packet_type = C.SECRET_SUBKEY_PACKET_TYPE
    if packets[0].type != key_packet_type:
        raise exceptions.InvalidKeyPacketOrder(
                "The first packet must be a Key Packet")
    pubkey_version = packets[0].version
    for i in range(len(type_order)):
        if i > 0:
            j = i - 1
            # Ignore trust packets
            while type_order[j] == C.TRUST_PACKET_TYPE:
                j -= 1
            previous = type_order[j]
        this = type_order[i]
        if this == key_packet_type:
            if i != 0:
                raise exceptions.InvalidKeyPacketOrder(
                        "Public Key Packet must be first in the list")
        elif this == C.SIGNATURE_PACKET_TYPE:
            sig_type = packets[i].signature_type
            previous_non_sig = [x for x in type_order[j::-1] if x not in (
                                C.SIGNATURE_PACKET_TYPE, C.TRUST_PACKET_TYPE)][0]
            if sig_type == C.SIGNATURE_DIRECTLY_ON_A_KEY:
                for t in type_order[:i]:
                    if t not in (key_packet_type,
                                 C.SIGNATURE_PACKET_TYPE):
                        raise exceptions.InvalidKeyPacketOrder(
                                    "Signature Directly On Key may only "
                                    "appear immediately after the Public Key "
                                    "Packet")
            elif sig_type == C.SUBKEY_BINDING_SIGNATURE:
                if previous_non_sig != subkey_packet_type:
                    raise exceptions.InvalidKeyPacketOrder(
                                "Subkey Binding Signature may only appear "
                                "immediately after a Subkey Packet, not {0}".format(previous))
                if previous == C.SIGNATURE_PACKET_TYPE and packets[j].signature_type != C.SUBKEY_BINDING_SIGNATURE:
                    raise exceptions.InvalidKeyPacketOrder(
                                "Subkey Binding Signature may only appear "
                                "immediately after a Subkey Packet, not {0}".format(previous))
            elif sig_type == C.KEY_REVOCATION_SIGNATURE:
                for t in type_order[:i]:
                    if t not in (key_packet_type,
                                 C.SIGNATURE_PACKET_TYPE,
                                 C.TRUST_PACKET_TYPE):
                        raise exceptions.InvalidKeyPacketOrder(
                                    "Key Revocation Signature may only "
                                    "appear immediately after the Public Key "
                                    "Packet and other Signatures Directly On "
                                    "Key")
            elif sig_type == C.SUBKEY_REVOCATION_SIGNATURE:
                if (previous != C.SIGNATURE_PACKET_TYPE
                        or packets[j].signature_type != C.SUBKEY_REVOCATION_SIGNATURE):
                    raise exceptions.InvalidKeyPacketOrder(
                                "Subkey Revocation Signature may only appear "
                                "after a Subkey Binding Signature")
            elif sig_type in (C.GENERIC_CERTIFICATION, C.PERSONA_CERTIFICATION,
                              C.CASUAL_CERTIFICATION, C.POSITIVE_CERTIFICATION,
                              C.CERTIFICATION_REVOCATION_SIGNATURE):
                if previous_non_sig not in (C.USER_ID_PACKET_TYPE,
                                            C.USER_ATTRIBUTE_PACKET_TYPE,
                                            C.TRUST_PACKET_TYPE):
                    raise exceptions.InvalidKeyPacketOrder(
                                "Certifications must apply to user IDs or "
                                "user attributes, not {0}".format(previous_non_sig))
            else:
                raise exceptions.InvalidKeyPacketType(
                            "Invalid signature type for transferrable "
                            "public key, 0x{0:02x}.".format(sig_type))
        elif this == C.USER_ID_PACKET_TYPE:
            for t in type_order[:i]:
                if t not in (key_packet_type, C.SIGNATURE_PACKET_TYPE,
                             C.USER_ID_PACKET_TYPE, C.TRUST_PACKET_TYPE):
                    raise exceptions.InvalidKeyPacketOrder(
                                "User IDs must appear before all user "
                                "attributes and subkeys")
        elif this == C.USER_ATTRIBUTE_PACKET_TYPE:
            for t in type_order[:i]:
                if t not in (key_packet_type, C.SIGNATURE_PACKET_TYPE,
                             C.USER_ID_PACKET_TYPE, C.USER_ATTRIBUTE_PACKET_TYPE,
                             C.TRUST_PACKET_TYPE):
                    raise exceptions.InvalidKeyPacketOrder(
                                "User attributes must appear before all "
                                "subkeys")
        elif this in (C.PUBLIC_SUBKEY_PACKET_TYPE, C.SECRET_SUBKEY_PACKET_TYPE):
            if pubkey_version < 4:
                raise exceptions.InvalidKeyPacketType(
                            "V3 keys may not contain subkeys")
            if (type_order[i + 1] != C.SIGNATURE_PACKET_TYPE
                or packets[i + 1].signature_type != C.SUBKEY_BINDING_SIGNATURE):

                raise exceptions.InvalidKeyPacketOrder(
                            "Subkeys must be followed by a binding signature")
        elif this == C.TRUST_PACKET_TYPE:
            if previous != C.SIGNATURE_PACKET_TYPE:
                raise exceptions.InvalidKeyPacketOrder(
                            "Trust packets may only follow signature packets")
        else:
            raise exceptions.InvalidKeyPacketType(this)


@provider(interfaces.ITransferablePublicKeyFactory)
@implementer(interfaces.ITransferablePublicKey)
class TransferablePublicKey(BasePublicKey):

    _SubkeyClass = PublicSubkey
    _secret = False

    @classmethod
    def from_packets(cls, packets):
        # TODO: HANDLE TRUST PACKETS
        packets = list(packets)
        validate_transferrable_key(packets, cls._secret)
        i = 0
        primary_public_key = cls.from_packet(packets[i])
        primary_public_key_signatures = []
        i += 1
        packet_count = len(packets)
        while i < packet_count and packets[i].type == C.SIGNATURE_PACKET_TYPE:
            primary_public_key_signatures.append(
                    KeySignature.from_packet(packets[i],
                                             primary_public_key)
                )
            i += 1

        primary_public_key.signatures = primary_public_key_signatures
        user_ids = primary_public_key.user_ids
        while i < packet_count and packets[i].type == C.USER_ID_PACKET_TYPE:
            user_id = UserID.from_packet(primary_public_key, packets[i])
            user_ids.append(user_id)
            i += 1
            while (
                i < packet_count
                and packets[i].type == C.SIGNATURE_PACKET_TYPE
                ):

                user_id.signatures.append(
                        KeySignature.from_packet(packets[i],
                                                 user_id)
                    )
                i += 1

        user_attributes = primary_public_key.user_attributes
        while (
            i < packet_count
            and packets[i].type == C.USER_ATTRIBUTE_PACKET_TYPE
            ):

            user_attribute = UserAttribute.from_packet(primary_public_key,
                                                       packets[i])
            user_attributes.append(user_attribute)
            i += 1
            while (
                i < packet_count
                and packets[i].type == C.SIGNATURE_PACKET_TYPE
                ):

                user_attribute.signatures.append(
                        KeySignature.from_packet(packets[i],
                                                 user_attribute)
                    )
                i += 1

        subkeys = primary_public_key.subkeys
        while (
            i < packet_count
            and packets[i].type in (
                C.PUBLIC_SUBKEY_PACKET_TYPE,
                C.SECRET_SUBKEY_PACKET_TYPE
                )
            ):

            subkey = cls._SubkeyClass.from_packet(primary_public_key,
                                                  packets[i])
            subkeys.append(subkey)
            i += 1
            while (
                i < packet_count
                and packets[i].type == C.SIGNATURE_PACKET_TYPE
                ):

                subkey.signatures.append(
                        KeySignature.from_packet(packets[i],
                                                 subkey)
                    )
                i += 1

        return primary_public_key

    def to_packets(self, header_format=None):
        packets = []
        packets.append(self.to_packet(header_format))
        for sig in self.signatures:
            packets.append(sig.to_packet(header_format))
        for user_id in self.user_ids:
            packets.append(user_id.to_packet(header_format))
            for sig in user_id.signatures:
                packets.append(sig.to_packet(header_format))
        for user_attribute in self.user_attributes:
            packets.append(user_attribute.to_packet(header_format))
            for sig in user_attribute.signatures:
                packets.append(sig.to_packet(header_format))
        for subkey in self.subkeys:
            packets.append(subkey.to_packet(header_format))
            for sig in subkey.signatures:
                packets.append(sig.to_packet(header_format))
        return packets

    def __init__(self, *args, **kwargs):
        BasePublicKey.__init__(self, *args, **kwargs)
        self.user_ids = []
        self.user_attributes = []
        self.subkeys = []


@provider(interfaces.ITransferableSecretKeyFactory)
@implementer(interfaces.ITransferableSecretKey)
class TransferableSecretKey(BaseSecretKey, TransferablePublicKey):

    _SubkeyClass = SecretSubkey
    _PublicClass = TransferablePublicKey
    _PacketClass = packets.SecretKeyPacket
    _secret = True

    def __init__(self, *args, **kwargs):
        BaseSecretKey.__init__(self, *args, **kwargs)
        self.user_ids = []
        self.user_attributes = []
        self.subkeys = []

    def to_public_key(self):
        key = super(TransferableSecretKey, self).to_public_key()
        key.user_ids = self.user_ids
        key.user_attributes = self.user_attributes
        key.subkeys = list(map(lambda k: k.to_public_key(), self.subkeys))
        return key

    def unlock(self, passphrase):
        super(TransferableSecretKey, self).unlock(passphrase)
        for sk in self.subkeys:
            sk.unlock(passphrase)

    def lock(self):
        super(TransferableSecretKey, self).lock()
        for sk in self.subkeys:
            sk.lock()
