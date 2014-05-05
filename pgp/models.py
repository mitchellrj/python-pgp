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
import re
import time
import weakref

from Crypto.Hash import MD5
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
from pgp.regex import validate_subpacket_regex
from pgp.user_id import parse_user_id
from pgp import utils


_marker = object()


@implementer(interfaces.INotation)
class Notation(object):

    namespace = None
    name = None
    value = None

    @classmethod
    def from_subpacket(cls, subpacket):
        if subpacket.critical:
            # We don't understand what any notations mean really.
            raise exceptions.CannotParseCriticalNotation
        return cls(subpacket.namespace, subpacket.name, subpacket.value,
                   subpacket.human_readable)

    def to_subpacket(self):
        return signature_subpackets.NotationSubpacket(
                critical=False,
                name=self.name,
                namespace=self.namespace,
                human_readable=self.is_human_readable(),
                value=self.value,
                )

    def __init__(self, namespace, name, value, human_readable):
        self.namespace = namespace
        self.name = name
        self.value = value
        self.human_readable = human_readable

    def is_human_readable(self):
        return self.human_readable


@implementer(interfaces.IRevocationKeyInfo)
class RevocationKeyInfo(object):

    public_key_algorithm = None
    fingerprint = None
    sensitive = None

    @classmethod
    def from_subpacket(cls, subpacket):
        return cls(subpacket.public_key_algorithm,
                   subpacket.fingerprint,
                   subpacket.sensitive)

    def to_subpacket(self, critical=False):
        return signature_subpackets.RevocationKeySubpacket(
                    critical,
                    self.fingerprint,
                    self.public_key_algorithm,
                    self.sensitive,
                )

    def __init__(self, public_key_algorithm, fingerprint, sensitive=False):
        self.public_key_algorithm = public_key_algorithm
        self.fingerprint = fingerprint
        self.sensitive = sensitive


@implementer(interfaces.ISignature)
class Signature(object):

    NotationClass = Notation
    RevocationKeyInfoClass = RevocationKeyInfo

    version = None
    signature_type = None
    public_key_algorithm = None
    hash_algorithm = None
    hash2 = None
    signature_values = None

    # Information about the signature
    creation_time = None
    issuer_key_ids = None
    expiration_time = None
    exportable = None
    trust_depth = None
    trust_amount = None
    regular_expressions = None
    revocable = None
    notations = None
    issuer_user_id = None
    issuer_user_name = None
    issuer_user_email = None
    issuer_user_comment = None
    revocation_reason = None
    revocation_code = None
    embedded_signatures = None

    # Information about the thing the signature is applied to
    key_expiration_time = None
    preferred_compression_algorithms = None
    preferred_hash_algorithms = None
    preferred_symmetric_algorithms = None
    revocation_keys = None
    key_server_should_not_modify = None
    preferred_key_server = None
    primary_user_id = None
    policy_uri = None
    may_certify_others = None
    may_sign_data = None
    may_encrypt_comms = None
    may_encrypt_storage = None
    may_be_used_for_auth = None
    may_have_been_split = None
    may_have_multiple_owners = None
    supports_modification_detection = None

    @staticmethod
    def _make_regex(subpacket):
        validate_subpacket_regex(subpacket.pattern)
        return re.compile(subpacket.pattern)

    @staticmethod
    def _from_subpackets(packet, type_, attr=None, constructor=None,
                         return_all=False, default=_marker):
        ignore_subpacket_exceptions = (
                exceptions.CannotParseCritical,
                exceptions.RegexValueError
            )
        if return_all:
            result = []
        else:
            result = default
        for subpacket in packet.unhashed_subpackets:
            item = default
            if subpacket.type != type_:
                continue
            if attr is not None:
                item = getattr(subpacket, attr, default)
            else:
                try:
                    item = constructor(subpacket)
                except ignore_subpacket_exceptions:
                    # Handled by "if item is not default" below
                    pass
            if return_all:
                if item is not default:
                    result.append(item)
            else:
                result = item
        for subpacket in packet.hashed_subpackets:
            item = default
            if subpacket.type != type_:
                continue
            if attr is not None:
                item = getattr(subpacket, attr, default)
            else:
                try:
                    item = constructor(subpacket)
                except ignore_subpacket_exceptions:
                    # Handled by "if item is not default" below
                    pass
            if return_all:
                if item is not default:
                    result.append(item)
            else:
                result = item
        if not return_all and result is _marker:
            raise ValueError
        return result

    @classmethod
    def from_packet(cls, packet, target):
        version = packet.version
        signature_type = packet.signature_type
        public_key_algorithm = packet.public_key_algorithm
        hash_algorithm = packet.hash_algorithm,
        hash2 = packet.hash2
        signature_values = packet.signature_values
        if version in (2, 3):
            creation_time = datetime.datetime.fromtimestamp(
                                packet.creation_time)
            issuer_key_ids = [packet.key_id]
            expiration_time = None
            exportable = True
            trust_depth = None
            trust_amount = None
            regular_expressions = []
            revocable = True
            notations = []
            issuer_user_id = None
            revocation_reason = None
            revocation_code = None
            embedded_signatures = []
            key_expiration_time = None
            preferred_compression_algorithms = []
            preferred_hash_algorithms = []
            preferred_symmetric_algorithms = []
            revocation_keys = []
            key_server_should_not_modify = False
            preferred_key_server = None
            primary_user_id = False
            policy_uri = None
            may_certify_others = True
            may_sign_data = True
            may_encrypt_comms = True
            may_encrypt_storage = True
            may_be_used_for_auth = True
            may_have_been_split = True
            may_have_multiple_owners = True
            supports_modification_detection = False
        elif version >= 4:
            creation_time = datetime.datetime.fromtimestamp(
                cls._from_subpackets(
                    packet,
                    C.CREATION_TIME_SUBPACKET_TYPE,
                    'time',
                    default=None
                ))
            expiration_seconds = cls._from_subpackets(
                    packet,
                    C.EXPIRATION_SECONDS_SUBPACKET_TYPE,
                    'time',
                    default=None)
            expiration_time = None
            if expiration_seconds is not None:
                expiration_time = (
                    creation_time +
                    datetime.timedelta(seconds=expiration_seconds)
                    )
            exportable = cls._from_subpackets(
                    packet,
                    C.EXPORTABLE_SUBPACKET_TYPE,
                    'exportable',
                    default=True)
            trust_depth = cls._from_subpackets(
                    packet,
                    C.TRUST_SUBPACKET_TYPE,
                    'depth',
                    default=None)
            trust_amount = cls._from_subpackets(
                    packet,
                    C.TRUST_SUBPACKET_TYPE,
                    'amount',
                    default=None)
            revocable = cls._from_subpackets(
                    packet,
                    C.REVOCABLE_SUBPACKET_TYPE,
                    'revocable',
                    default=True)
            issuer_user_id = cls._from_subpackets(
                    packet,
                    C.ISSUERS_USER_ID_SUBPACKET_TYPE,
                    'user_id',
                    default=None)
            revocation_reason = cls._from_subpackets(
                    packet,
                    C.REVOCATION_REASON_SUBPACKET_TYPE,
                    'revocation_reason',
                    default=None)
            revocation_code = cls._from_subpackets(
                    packet,
                    C.REVOCATION_REASON_SUBPACKET_TYPE,
                    'revocation_code',
                    default=None)
            key_expiration_seconds = cls._from_subpackets(
                    packet,
                    C.KEY_EXPIRATION_TIME_SUBPACKET_TYPE,
                    'time',
                    default=None)
            key_expiration_time = None
            if key_expiration_seconds is not None:
                key_expiration_time = (
                    target.creation_time +
                    datetime.timedelta(seconds=key_expiration_seconds)
                    )
            preferred_compression_algorithms = cls._from_subpackets(
                    packet,
                    C.PREFERRED_COMPRESSION_ALGORITHMS_SUBPACKET_TYPE,
                    'preferred_algorithms',
                    default=[])
            preferred_hash_algorithms = cls._from_subpackets(
                    packet,
                    C.PREFERRED_HASH_ALGORITHMS_SUBPACKET_TYPE,
                    'preferred_algorithms',
                    default=[])
            preferred_symmetric_algorithms = cls._from_subpackets(
                    packet,
                    C.PREFERRED_SYMMETRIC_ALGORITHMS_SUBPACKET_TYPE,
                    'preferred_algorithms',
                    default=[])
            key_server_should_not_modify = cls._from_subpackets(
                    packet,
                    C.KEY_SERVER_PREFERENCES_SUBPACKET_TYPE,
                    'no_modify',
                    default=False)
            preferred_key_server = cls._from_subpackets(
                    packet,
                    C.PREFERRED_KEY_SERVER_SUBPACKET_TYPE,
                    'uri',
                    default=None)
            primary_user_id = cls._from_subpackets(
                    packet,
                    C.PRIMARY_USER_ID_SUBPACKET_TYPE,
                    'primary',
                    default=False)
            policy_uri = cls._from_subpackets(
                    packet,
                    C.POLICY_URI_SUBPACKET_TYPE,
                    'uri',
                    default=None)
            may_certify_others = cls._from_subpackets(
                    packet,
                    C.KEY_FLAGS_SUBPACKET_TYPE,
                    'may_certify_others',
                    default=True)
            may_sign_data = cls._from_subpackets(
                    packet,
                    C.KEY_FLAGS_SUBPACKET_TYPE,
                    'may_sign_data',
                    default=True)
            may_encrypt_comms = cls._from_subpackets(
                    packet,
                    C.KEY_FLAGS_SUBPACKET_TYPE,
                    'may_encrypt_comms',
                    default=True)
            may_encrypt_storage = cls._from_subpackets(
                    packet,
                    C.KEY_FLAGS_SUBPACKET_TYPE,
                    'may_encrypt_storage',
                    default=True)
            may_be_used_for_auth = cls._from_subpackets(
                    packet,
                    C.KEY_FLAGS_SUBPACKET_TYPE,
                    'may_be_used_for_auth',
                    default=True)
            may_have_been_split = cls._from_subpackets(
                    packet,
                    C.KEY_FLAGS_SUBPACKET_TYPE,
                    'may_have_been_split',
                    default=True)
            may_have_multiple_owners = cls._from_subpackets(
                    packet,
                    C.KEY_FLAGS_SUBPACKET_TYPE,
                    'may_have_multiple_owners',
                    default=True)
            supports_modification_detection = cls._from_subpackets(
                    packet,
                    C.FEATURES_SUBPACKET_TYPE,
                    'supports_modification_detection',
                    default=False)
            issuer_key_ids = cls._from_subpackets(
                    packet,
                    C.ISSUER_KEY_ID_SUBPACKET_TYPE,
                    'key_id',
                    default=[],
                    return_all=True)
            revocation_keys = cls._from_subpackets(
                    packet,
                    C.REVOCATION_KEY_SUBPACKET_TYPE,
                    constructor=cls.RevocationKeyInfoClass.from_subpacket,
                    return_all=True)
            regular_expressions = cls._from_subpackets(
                    packet,
                    C.REGULAR_EXPRESSION_SUBPACKET_TYPE,
                    constructor=cls._make_regex,
                    return_all=True)
            notations = cls._from_subpackets(
                    packet,
                    C.NOTATION_SUBPACKET_TYPE,
                    constructor=cls.NotationClass.from_subpacket,
                    return_all=True)
            embedded_signatures = cls._from_subpackets(
                    packet,
                    C.EMBEDDED_SIGNATURE_SUBPACKET_TYPE,
                    constructor=cls.from_packet,
                    return_all=True)
        else:
            raise ValueError

        return cls(target, version, signature_type, public_key_algorithm,
                   hash_algorithm, hash2, signature_values, creation_time,
                   issuer_key_ids, expiration_time, exportable, trust_depth,
                   trust_amount, regular_expressions, revocable, notations,
                   issuer_user_id, revocation_reason, revocation_code,
                   embedded_signatures, key_expiration_time,
                   preferred_compression_algorithms,
                   preferred_hash_algorithms, preferred_symmetric_algorithms,
                   revocation_keys, key_server_should_not_modify,
                   preferred_key_server, primary_user_id, policy_uri,
                   may_certify_others, may_sign_data, may_encrypt_comms,
                   may_encrypt_storage, may_be_used_for_auth,
                   may_have_been_split, may_have_multiple_owners,
                   supports_modification_detection)

    def to_packet(self, header_format, hash_subpackets=None,
                  critical_subpackets=None):
        if self.version >= 4:
            # Use subpackets
            if critical_subpackets is None:
                critical_subpackets = []
            hashed_subpackets = []
            unhashed_subpackets = []
            is_critical = lambda subtype: subtype in critical_subpackets
            subpacket_list = lambda subtype: (
                    hashed_subpackets
                    if (
                        hash_subpackets is None or
                        subtype in hash_subpackets
                        )
                    else unhashed_subpackets
                )

            crit = is_critical(C.CREATION_TIME_SUBPACKET_TYPE)
            creation_time = int(time.mktime(self.creation_time.timetuple()))
            hashed_subpackets.append(
                signature_subpackets.CreationTimeSubpacket(crit,
                                                           creation_time)
                )

            crit = is_critical(C.EXPIRATION_SECONDS_SUBPACKET_TYPE)
            expiration_seconds = (
                    self.expiration_time - self.creation_time).seconds
            subpacket_list(C.EXPIRATION_SECONDS_SUBPACKET_TYPE).append(
                signature_subpackets.ExpirationSecondsSubpacket(
                        crit, expiration_seconds)
                )

            crit = is_critical(C.EXPORTABLE_SUBPACKET_TYPE)
            subpacket_list(C.EXPORTABLE_SUBPACKET_TYPE).append(
                signature_subpackets.ExportableSubpacket(
                        crit, self.exportable)
                )

            crit = is_critical(C.TRUST_SUBPACKET_TYPE)
            subpacket_list(C.TRUST_SUBPACKET_TYPE).append(
                signature_subpackets.TrustSubpacket(
                        crit, self.trust_depth, self.trust_amount)
                )

            crit = is_critical(C.REGULAR_EXPRESSION_SUBPACKET_TYPE)
            subpacket_list(C.REGULAR_EXPRESSION_SUBPACKET_TYPE).extend([
                signature_subpackets.RegularExpressionSubpacket(
                        crit, regex.pattern
                    )
                for regex in self.regular_expressions
                ])

            crit = is_critical(C.REVOCABLE_SUBPACKET_TYPE)
            subpacket_list(C.REVOCABLE_SUBPACKET_TYPE).append(
                signature_subpackets.RevocableSubpacket(
                        crit, self.revocable)
                )

            crit = is_critical(C.KEY_EXPIRATION_TIME_SUBPACKET_TYPE)
            key_expiration_time = int(time.mktime(
                        self.key_expiration_time.timetuple()))
            subpacket_list(C.KEY_EXPIRATION_TIME_SUBPACKET_TYPE).append(
                signature_subpackets.KeyExpirationTimeSubpacket(
                        crit, key_expiration_time)
                )

            sub_type = C.PREFERRED_SYMMETRIC_ALGORITHMS_SUBPACKET_TYPE
            crit = is_critical(sub_type)
            subpacket_list(sub_type).append(
                signature_subpackets.PreferredSymmetricAlgorithmsSubpacket(
                        crit, self.preferred_symettric_algorithms)
                )

            crit = is_critical(C.REVOCATION_KEY_SUBPACKET_TYPE)
            subpacket_list(C.REVOCATION_KEY_SUBPACKET_TYPE).extend([
                revocation_key_info.to_subpacket(crit)
                for revocation_key_info in self.revocation_keys
                ])

            crit = is_critical(C.ISSUER_KEY_ID_SUBPACKET_TYPE)
            subpacket_list(C.ISSUER_KEY_ID_SUBPACKET_TYPE).extend([
                signature_subpackets.IssuerSubpacket(crit, key_id)
                for key_id in self.issuer_key_ids
                ])

            crit = is_critical(C.NOTATION_SUBPACKET_TYPE)
            subpacket_list(C.NOTATION_SUBPACKET_TYPE).extend([
                notation.to_subpacket(crit)
                for notation in self.notations
                ])

            sub_type = C.PREFERRED_HASH_ALGORITHMS_SUBPACKET_TYPE
            crit = is_critical(sub_type)
            subpacket_list(sub_type).append(
                signature_subpackets.PreferredHashAlgorithmsSubpacket(
                        crit, self.preferred_hash_algorithms)
                )

            sub_type = C.PREFERRED_COMPRESSION_ALGORITHMS_SUBPACKET_TYPE
            crit = is_critical(sub_type)
            subpacket_list(sub_type).append(
                signature_subpackets.PreferredCompressionAlgorithmsSubpacket(
                        crit, self.preferred_compression_algorithms)
                )

            crit = is_critical(C.KEY_SERVER_PREFERENCES_SUBPACKET_TYPE)
            subpacket_list(C.KEY_SERVER_PREFERENCES_SUBPACKET_TYPE).append(
                signature_subpackets.KeyServerPreferencesSubpacket(
                        crit, self.key_server_should_not_modify)
                )

            crit = is_critical(C.PREFERRED_KEY_SERVER_SUBPACKET_TYPE)
            subpacket_list(C.PREFERRED_KEY_SERVER_SUBPACKET_TYPE).append(
                signature_subpackets.PreferredKeyServerSubpacket(
                        crit, self.preferred_key_server)
                )

            crit = is_critical(C.PRIMARY_USER_ID_SUBPACKET_TYPE)
            subpacket_list(C.PRIMARY_USER_ID_SUBPACKET_TYPE).append(
                signature_subpackets.PrimaryUserIDSubpacket(
                        crit, self.primary_user_id)
                )

            crit = is_critical(C.POLICY_URI_SUBPACKET_TYPE)
            subpacket_list(C.POLICY_URI_SUBPACKET_TYPE).append(
                signature_subpackets.PolicyURISubpacket(
                        crit, self.policy_uri)
                )

            crit = is_critical(C.KEY_FLAGS_SUBPACKET_TYPE)
            subpacket_list(C.KEY_FLAGS_SUBPACKET_TYPE).append(
                signature_subpackets.KeyFlagsSubpacket(
                        crit,
                        self.may_certify_others,
                        self.may_sign_data,
                        self.may_encrypt_comms,
                        self.may_encrypt_storage,
                        self.may_be_used_for_auth,
                        self.may_have_been_split,
                        self.may_have_multiple_owners,
                        )
                )

            crit = is_critical(C.ISSUERS_USER_ID_SUBPACKET_TYPE)
            subpacket_list(C.ISSUERS_USER_ID_SUBPACKET_TYPE).append(
                signature_subpackets.UserIDSubpacket(
                        crit, self.issuer_user_id)
                )

            crit = is_critical(C.REVOCATION_REASON_SUBPACKET_TYPE)
            subpacket_list(C.REVOCATION_REASON_SUBPACKET_TYPE).append(
                signature_subpackets.RevocationReasonSubpacket(
                        crit, self.revocation_code, self.revocation_reason)
                )

            crit = is_critical(C.FEATURES_SUBPACKET_TYPE)
            subpacket_list(C.FEATURES_SUBPACKET_TYPE).append(
                signature_subpackets.FeaturesSubpacket(
                        crit, self.supports_modification_detection)
                )

            crit = is_critical(C.EMBEDDED_SIGNATURE_SUBPACKET_TYPE)
            subpacket_list(C.EMBEDDED_SIGNATURE_SUBPACKET_TYPE).extend([
                signature_subpackets.EmbeddedSignatureSubpacket(
                        crit,
                        signature.to_packet(
                            header_format,
                            hash_subpackets=hash_subpackets,
                            critical_subpackets=critical_subpackets,
                            )
                        )
                for signature in self.embedded_signatures
                ])
            # Set target hash etc
            packet = packets.SignaturePacket(
                        header_format, self.version, self.signature_type,
                        self.public_key_algorithm, self.hash_algorithm,
                        self.hash2, self.signature_values, hashed_subpackets,
                        unhashed_subpackets)
        elif self.version in (2, 3):
            creation_time = int(time.mktime(self.creation_time.timetuple()))
            packet = packets.SignaturePacket(
                        header_format, self.version, self.signature_type,
                        self.public_key_algorithm, self.hash_algorithm,
                        self.hash2, self.signature_values, creation_time,
                        self.issuer_key_ids[0])
        return packet

    def __repr__(self):
        return '<{0} 0x{1:02x} at 0x{2:x}>'.format(self.__class__.__name__,
                                                   self.signature_type,
                                                   id(self))

    def __init__(self, target, version, signature_type, public_key_algorithm,
                 hash_algorithm, hash2, signature_values, creation_time,
                 issuer_key_ids, expiration_time=None, exportable=None,
                 trust_depth=None, trust_amount=None,
                 regular_expressions=None, revocable=None, notations=None,
                 issuer_user_id=None, revocation_reason=None,
                 revocation_code=None, embedded_signatures=None,
                 key_expiration_time=None,
                 preferred_compression_algorithms=None,
                 preferred_hash_algorithms=None,
                 preferred_symmetric_algorithms=None,
                 revocation_keys=None, key_server_should_not_modify=None,
                 preferred_key_server=None, primary_user_id=None,
                 policy_uri=None, may_certify_others=None, may_sign_data=None,
                 may_encrypt_comms=None, may_encrypt_storage=None,
                 may_be_used_for_auth=None, may_have_been_split=None,
                 may_have_multiple_owners=None,
                 supports_modification_detection=None):

        self._target_ref = weakref.ref(target)
        self.version = version
        self.signature_type = signature_type
        self.public_key_algorithm = public_key_algorithm
        self.hash_algorithm = hash_algorithm
        self.hash2 = hash2
        self.signature_values = signature_values
        self.creation_time = creation_time
        self.issuer_key_ids = issuer_key_ids
        self.expiration_time = expiration_time
        self.exportable = exportable
        self.trust_depth = trust_depth
        self.trust_amount = trust_amount
        self.regular_expressions = regular_expressions
        self.revocable = revocable
        self.notations = notations
        self.issuer_user_id = issuer_user_id
        self.revocation_reason = revocation_reason
        self.revocation_code = revocation_code
        self.embedded_signatures = embedded_signatures
        self.key_expiration_time = key_expiration_time
        self.preferred_compression_algorithms = \
            preferred_compression_algorithms
        self.preferred_hash_algorithms = preferred_hash_algorithms
        self.preferred_symmetric_algorithms = preferred_symmetric_algorithms
        self.revocation_keys = revocation_keys
        self.key_server_should_not_modify = key_server_should_not_modify
        self.preferred_key_server = preferred_key_server
        self.primary_user_id = primary_user_id
        self.policy_uri = policy_uri
        self.may_certify_others = may_certify_others
        self.may_sign_data = may_sign_data
        self.may_encrypt_comms = may_encrypt_comms
        self.may_encrypt_storage = may_encrypt_storage
        self.may_be_used_for_auth = may_be_used_for_auth
        self.may_have_been_split = may_have_been_split
        self.may_have_multiple_owners = may_have_multiple_owners
        self.supports_modification_detection = supports_modification_detection

    @property
    def target(self):
        # Resolve weakref
        return self._target_ref()

    def is_self_signature(self):
        target = self.target
        own_key_ids = []
        if isinstance(target, TransferablePublicKey):
            primary_public_key = target
        else:
            primary_public_key = target.primary_public_key

        own_key_ids.append(primary_public_key.key_id)
        for subkey in primary_public_key.subkeys:
            own_key_ids.append(subkey.key_id)

        return bool(set(self.issuer_key_ids) & set(own_key_ids))

    def is_expired(self):
        pass

    def is_revoked(self):
        pass

    def issuer_key_is_expired(self):
        pass

    def issuer_key_is_revoked(self):
        pass

    def signature_target(self):
        pass

    @property
    def issuer_user_name(self):
        if self.issuer_user_id is None:
            return None
        return parse_user_id(self.issuer_user_id)[0]

    @property
    def issuer_user_email(self):
        if self.issuer_user_id is None:
            return None
        return parse_user_id(self.issuer_user_id)[1]

    @property
    def issuer_user_comment(self):
        if self.issuer_user_id is None:
            return None
        return parse_user_id(self.issuer_user_id)[2]


@implementer(interfaces.IPublicKey)
class BasePublicKey(object):

    _self_sig_type = C.SIGNATURE_DIRECTLY_ON_A_KEY
    _revocation_sig_type = C.KEY_REVOCATION_SIGNATURE
    _PacketClass = packets.PublicKeyPacket

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
        return cls(*args)

    def to_packet(self, header_format=C.NEW_PACKET_HEADER_TYPE):
        creation_time = int(time.mktime(self.creation_time.timetuple()))
        expiration_days = None
        if self.version < 4:
            expiration_time = self.expiration_time
            if expiration_time is not None:
                expiration_days = (expiration_time - creation_time).days

        return self._PacketClass(
            header_format, self.version, creation_time,
            self.public_key_algorithm, expiration_days, self.modulus_n,
            self.exponent_e, self.prime_p, self.group_generator_g,
            self.group_order_q, self.key_value_y
            )

    def verify(self, signature):
        raise NotImplemented

    def encrypt(self, data):
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
        self.expiration_time = expiration_time

    def __repr__(self):
        return '<{0} 0x{1}>'.format(self.__class__.__name__,
                                    self.key_id)

    def is_revoked(self):
        for signature in self.signatures:
            if not signature.is_self_signature():
                continue
            if signature.type != self._revocation_sig_type:
                continue
            return True

        return False

    def is_expired(self):
        return self.expiration_time < datetime.datetime.now()

    def _get_expiration_time(self):
        expires = None
        if self.version < 4:
            expires = self._expiration_time
        else:
            last_signature_created = 0
            for signature in self.signatures:
                if not signature.is_self_signature():
                    continue
                if signature.type != self._self_sig_type:
                    continue
                if (signature.key_expiration_time is not None
                    and last_signature_created < signature.creation_time):
                    expires = signature.key_expiration_time

        return expires

    def _set_expiration_time(self, expiration_time):
        if self.version < 4:
            self._expiration_time = expiration_time
        else:
            last_signature_created = 0
            most_recent_selfsig = None
            for signature in self.signatures:
                if not signature.is_self_signature():
                    continue
                if signature.type != self._self_sig_type:
                    continue
                if last_signature_created < signature.creation_time:
                    most_recent_selfsig = signature

            if most_recent_selfsig is not None:
                most_recent_selfsig.key_expiration_time = \
                    expiration_time
            elif expiration_time:
                raise ValueError(
                        "Cannot set expiration time on V4 key with no "
                        "self-signature.")

    expiration_time = property(_get_expiration_time, _set_expiration_time)

    @property
    def _key_obj(self):
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
        if self.version < 4:
            md5 = MD5.new()
            # Key type must be RSA for v2 and v3 public keys
            if self.public_key_algorithm in (1, 2, 3):
                md5.update(utils.int_to_bytes(self.modulus_n))
                md5.update(utils.int_to_bytes(self.exponent_e))
            elif self.public_key_algorithm in (16, 20):
                md5.update(utils.int_to_bytes(self.prime_p))
                md5.update(utils.int_to_bytes(self.group_generator_g))
            fingerprint = md5.hexdigest().upper()
        elif self.version >= 4:
            sha1 = SHA.new()
            pubkey_data = self.to_packet().content
            pubkey_length = len(pubkey_data)
            seed_bytes = (
                    0x99,
                    (pubkey_length >> 8) & 0xff,
                    pubkey_length & 0xff
                )
            sha1.update(bytearray(seed_bytes))
            sha1.update(pubkey_data)
            fingerprint = sha1.hexdigest().upper()
        return fingerprint

    @staticmethod
    def __selfsig_attribute(name, default=None):
        def getter(self):
            result = default
            if self.version >= 4:
                last_signature_created = 0
                most_recent_selfsig = None
                for signature in self.signatures:
                    if not signature.is_self_signature():
                        continue
                    if signature.type != self._self_sig_type:
                        continue
                    if last_signature_created < signature.creation_time:
                        most_recent_selfsig = signature

                result = getattr(most_recent_selfsig, name, default)

            return result

        return property(getter)

    __selfsig_attribute = __selfsig_attribute.__func__

    preferred_compression_algorithms = \
        __selfsig_attribute('preferred_compression_algorithms', [])
    preferred_hash_algorithms = \
        __selfsig_attribute('preferred_hash_algorithms', [])
    preferred_symmetric_algorithms = \
        __selfsig_attribute('preferred_symmetric_algorithms', [])
    revocation_keys = \
        __selfsig_attribute('revocation_keys', [])
    key_server_should_not_modify = \
        __selfsig_attribute('key_server_should_not_modify', False)
    preferred_key_server = __selfsig_attribute('preferred_key_server')
    primary_user_id = __selfsig_attribute('primary_user_id')
    policy_uri = __selfsig_attribute('policy_uri')
    may_certify_others = __selfsig_attribute('may_certify_others', True)
    may_sign_data = __selfsig_attribute('may_sign_data', True)
    may_encrypt_comms = __selfsig_attribute('may_encrypt_comms', True)
    may_encrypt_storage = __selfsig_attribute('may_encrypt_comms', True)
    may_be_used_for_auth = __selfsig_attribute('may_encrypt_comms', True)
    may_have_been_split = __selfsig_attribute('may_have_been_split', True)
    may_have_multiple_owners = \
        __selfsig_attribute('may_have_multiple_owners', True)
    supports_modification_detection = \
        __selfsig_attribute('may_have_multiple_owners', False)

    del __selfsig_attribute


class PublicSubkey(BasePublicKey):

    _self_sig_type = C.SUBKEY_BINDING_SIGNATURE
    _revocation_sig_type = C.SUBKEY_REVOCATION_SIGNATURE
    _PacketClass = packets.PublicSubkeyPacket

    @classmethod
    def from_packet(cls, primary_public_key, packet):
        args = cls._init_args_from_packet(packet)
        return cls(primary_public_key, *args)

    def __init__(self, primary_public_key, *args, **kwargs):
        self._primary_public_key_ref = weakref.ref(primary_public_key)
        BasePublicKey.__init__(self, *args, **kwargs)

    @property
    def primary_public_key(self):
        return self._primary_public_key_ref()


@implementer(interfaces.IUserID)
class UserID(object):

    signatures = None

    @classmethod
    def from_packet(cls, primary_public_key, packet):
        return cls(primary_public_key, packet.user_id, [])

    def to_packet(self, header_format=C.NEW_PACKET_HEADER_TYPE):
        return packets.UserIDPacket(self.user_id)

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

    def is_primary_user_id(self):
        pass


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
class UserAttribute(object):

    content_items = None
    signatures = None

    @classmethod
    def from_packet(cls, primary_public_key, packet):
        content_items = []
        for sp in packet.subpackets:
            content_items.append(UserAttributeContentItem.from_subpacket(sp))
        return cls(primary_public_key, content_items)

    def to_packet(self, header_format=C.NEW_PACKET_HEADER_TYPE):
        subpackets = []
        for item in self.content_items:
            subpackets.append(item.to_packet(header_format))
        return packets.UserAttributePacket(header_format, subpackets)

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


def validate_transferrable_public_key(packets):
    # http://tools.ietf.org/html/rfc4880#section-11.1

    type_order = list(map(lambda p: p.type, packets))
    previous = None
    if packets[0].type != 6:
        raise exceptions.InvalidKeyPacketOrder(
                "The first packet must be a Public Key Packet")
    pubkey_version = packets[0].version
    for i in range(len(type_order)):
        if i > 0:
            previous = type_order[i - 1]
        this = type_order[i]
        if this == 6:
            if i != 0:
                raise exceptions.InvalidKeyPacketOrder(
                        "Public Key Packet must be first in the list")
        elif this == 2:
            sig_type = packets[i].signature_type
            previous_non_sig = [x for x in type_order[i - 1::-1] if x != 2][0]
            if sig_type == 0x1f:
                for t in type_order[:i]:
                    if t not in (6, 2):
                        raise exceptions.InvalidKeyPacketOrder(
                                    "Signature Directly On Key may only "
                                    "appear immediately after the Public Key "
                                    "Packet")
            elif sig_type == 0x18:
                if previous != 14:
                    raise exceptions.InvalidKeyPacketOrder(
                                "Subkey Binding Signature may only appear "
                                "immediately after a Subkey Packet")
            elif sig_type == 0x20:
                for t in type_order[:i]:
                    if t not in (6, 2):
                        raise exceptions.InvalidKeyPacketOrder(
                                    "Key Revocation Signature may only "
                                    "appear immediately after the Public Key "
                                    "Packet and other Signatures Directly On "
                                    "Key")
            elif sig_type == 0x28:
                if previous != 2 or packets[i - 1].sig_type != 0x18:
                    raise exceptions.InvalidKeyPacketOrder(
                                "Subkey Revocation Signature may only appear "
                                "after a Subkey Binding Signature")
            elif sig_type in (0x10, 0x11, 0x12, 0x13, 0x30):
                if previous_non_sig not in (13, 17):
                    raise exceptions.InvalidKeyPacketOrder(
                                "Certifications must apply to user IDs or "
                                "user attributes")
            else:
                raise exceptions.InvalidKeyPacketType(
                            "Invalid signature type for transferrable "
                            "public key, 0x{0:02x}.".format(sig_type))
        elif this == 13:
            for t in type_order[:i]:
                if t not in (6, 2, 13):
                    raise exceptions.InvalidKeyPacketOrder(
                                "User IDs must appear before all user "
                                "attributes and subkeys")
        elif this == 17:
            for t in type_order[:i]:
                if t not in (6, 2, 13, 17):
                    raise exceptions.InvalidKeyPacketOrder(
                                "User attributes must appear before all "
                                "subkeys")
        elif this == 14:
            if pubkey_version < 4:
                raise exceptions.InvalidKeyPacketType(
                            "V3 keys may not contain subkeys")
            if (type_order[i + 1] != 2
                or packets[i + 1].signature_type != 0x18):

                raise exceptions.InvalidKeyPacketOrder(
                            "Subkeys must be followed by a binding signature")
        else:
            raise exceptions.InvalidKeyPacketType()


@provider(interfaces.ITransferablePublicKeyFactory)
@implementer(interfaces.ITransferablePublicKey)
class TransferablePublicKey(BasePublicKey):

    _SubkeyClass = PublicSubkey

    @classmethod
    def from_packets(cls, packets):
        packets = list(packets)
        validate_transferrable_public_key(packets)
        i = 0
        primary_public_key = cls.from_packet(packets[i])
        primary_public_key_signatures = []
        i += 1
        packet_count = len(packets)
        while i < packet_count and packets[i].type == C.SIGNATURE_PACKET_TYPE:
            primary_public_key_signatures.append(
                    Signature.from_packet(packets[i],
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
                        Signature.from_packet(packets[i],
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
                        Signature.from_packet(packets[i],
                                              user_attribute)
                    )
                i += 1

        subkeys = primary_public_key.subkeys
        while (
            i < packet_count
            and packets[i].type == C.PUBLIC_SUBKEY_PACKET_TYPE
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
                        Signature.from_packet(packets[i],
                                              subkey)
                    )
                i += 1

        return primary_public_key

    def to_packets(self, header_format):
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


class TransferableSecretKey(TransferablePublicKey):
    pass


class OpenPGPMessage(object):
    pass


class EncryptedMessage(OpenPGPMessage):
    pass


class SignedMessage(OpenPGPMessage):
    pass


class CompressedMessage(OpenPGPMessage):
    pass


class LiteralMessage(OpenPGPMessage):
    pass


class DetachedSignature(object):
    pass
