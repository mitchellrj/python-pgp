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
import re
import time
import weakref

from zope.interface import implementer
from zope.interface import provider

from pgp import interfaces
from pgp import exceptions
from pgp import utils
from pgp.crc24 import crc24
from pgp.packets import constants as C
from pgp.packets import packets
from pgp.packets import signature_subpackets
from pgp.user_id import parse_user_id


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

    def __eq__(self, other):
        return bytes(self.to_subpacket()) == bytes(other.to_subpacket())

    def __hash__(self):
        return crc24(bytes(self.to_subpacket()))

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

    def __eq__(self, other):
        return bytes(self.to_subpacket()) == bytes(other.to_subpacket())

    def __hash__(self):
        return crc24(bytes(self.to_subpacket()))


@implementer(interfaces.ISignature)
class BaseSignature(object):

    NotationClass = Notation
    RevocationKeyInfoClass = RevocationKeyInfo

    version = None
    signature_type = None
    public_key_algorithm = None
    hash_algorithm = None
    hash2 = None
    signature_values = None
    validated = None
    issuer_key_expired = None
    issuer_key_revoked = None

    # Packet level options
    packet_header_type = C.NEW_PACKET_HEADER_TYPE

    @classmethod
    def from_packet(cls, packet, target):
        version = packet.version
        signature_type = packet.signature_type
        public_key_algorithm = packet.public_key_algorithm
        hash_algorithm = packet.hash_algorithm
        hash2 = packet.hash2
        signature_values = packet.signature_values
        if version in (2, 3):
            creation_time = datetime.datetime.fromtimestamp(
                                packet.creation_time)
            issuer_key_id = packet.key_id
            hashed_subpackets = []
            unhashed_subpackets = []
        elif version >= 4:
            creation_time = None
            issuer_key_id = None
            hashed_subpackets = packet.hashed_subpackets[:]
            unhashed_subpackets = packet.unhashed_subpackets[:]
        else:
            raise ValueError

        sig = cls(target, version, signature_type, public_key_algorithm,
                  hash_algorithm, hash2, signature_values, creation_time,
                  issuer_key_id, hashed_subpackets, unhashed_subpackets)

        sig.packet_header_type = packet.header_format

        return sig

    def to_packet(self, header_format=None):
        if header_format is None:
            header_format = self.packet_header_type
        if self.version >= 4:
            # Use subpackets
            hashed_subpackets = self.hashed_subpackets
            unhashed_subpackets = self.unhashed_subpackets
            # Set target hash etc
            packet = packets.SignaturePacket(
                        header_format, self.version, self.signature_type,
                        self.public_key_algorithm, self.hash_algorithm,
                        self.hash2, self.signature_values,
                        hashed_subpackets=hashed_subpackets,
                        unhashed_subpackets=unhashed_subpackets)
        elif self.version in (2, 3):
            creation_time = int(time.mktime(self.creation_time.timetuple()))
            packet = packets.SignaturePacket(
                        header_format, self.version, self.signature_type,
                        self.public_key_algorithm, self.hash_algorithm,
                        self.hash2, self.signature_values, creation_time,
                        self.issuer_key_ids[0])
        return packet

    def to_signable_data(self, signature_type, signature_version=3):
        result = bytearray()
        if self.version >= 4:
            result.append(self.version)
        result.append(self.signature_type)
        if self.version < 4:
            result.extend(utils.int_to_4byte(
                time.mktime(self.creation_time.timetuple())
            ))
        else:
            result.append(self.public_key_algorithm)
            result.append(self.hash_algorithm)
            hashed_subpacket_data = b''.join(
                map(bytes, self.hashed_subpackets))
            hashed_subpacket_length = len(hashed_subpacket_data)
            result.extend(utils.int_to_2byte(hashed_subpacket_length))
            result.extend(hashed_subpacket_data)
            result.append(self.version)
            result.append(255)
            result.extend(utils.int_to_4byte(hashed_subpacket_length + 6))
        return result

    def __repr__(self):
        validation = ''
        if self.validated is True:
            validation = 'validated '
        elif self.validated is False:
            validation = 'invalid '
        return '<{0} {1} by {2} {3}at 0x{4:x}>'.format(
            self.__class__.__name__,
            C.human_signature_types.get(self.signature_type, 'Unknown'),
            self.issuer_key_ids[0],
            validation,
            id(self))

    def __init__(self, target, version, signature_type, public_key_algorithm,
                 hash_algorithm, hash2, signature_values, creation_time=None,
                 issuer_key_id=None, hashed_subpackets=None,
                 unhashed_subpackets=None, current_time_fn=None):

        self._target_ref = weakref.ref(target)
        self.version = version
        self.signature_type = signature_type
        self.public_key_algorithm = public_key_algorithm
        self.hash_algorithm = hash_algorithm
        self.hash2 = hash2
        self.signature_values = signature_values
        if version in (2, 3):
            self._creation_time = creation_time
            self._issuer_key_id = issuer_key_id
        elif version >= 4:
            if creation_time is not None:
                self._creation_time = creation_time
            if issuer_key_id is not None:
                self.issuer_key_ids = [issuer_key_id]
        self.hashed_subpackets = hashed_subpackets or []
        self.unhashed_subpackets = unhashed_subpackets or []
        if current_time_fn is None:
            current_time_fn = datetime.datetime.now
        self.get_current_time = current_time_fn

    def __eq__(self, other):
        return bytes(self.to_packet()) == bytes(other.to_packet())

    def __hash__(self):
        return crc24(bytes(self.to_packet()))

    def _get_subpackets(self, type_):
        result = []
        for s in self.hashed_subpackets + self.unhashed_subpackets:
            if s.type == type_:
                result.append(s)
        return result

    def _add_subpacket(self, sp, hashed=True):
        if hashed:
            self.hashed_subpackets.append(sp)
        else:
            self.unhashed_subpackets.append(sp)

    def _remove_subpacket(self, sp):
        while sp in self.hashed_subpackets:
            self.hashed_subpackets.remove(sp)
        while sp in self.unhashed_subpackets:
            self.unhashed_subpackets.remove(sp)

    def _get_subpacket_values(self, type_, attr, as_list=False):
        subpackets = self._get_subpackets(type_)
        if as_list:
            result = []
            for s in subpackets:
                result.append(getattr(s, attr))
        elif subpackets:
            result = getattr(subpackets[0], attr)
        else:
            result = None
        return result

    def _update_subpacket_values(self, type_, attr, value):
        subpackets = self._get_subpackets(type_)
        if subpackets:
            for s in subpackets:
                setattr(s, attr, value)
        else:
            self._add_subpacket_values(type_, attr, value)

    def _add_subpacket_values(self, type_, attr, value, hashed=True,
                              critical=False):
        sub = signature_subpackets.SIGNATURE_SUBPACKET_TYPES[type_](
                **{attr: value, 'critical': critical})
        self._add_subpacket(sub)

    def _remove_subpacket_values(self, type_, attr, value):
        subpackets = self._get_subpackets(type_)
        for sp in subpackets:
            if getattr(sp, attr) == value:
                self._remove_subpacket(sp)

    def _get_creation_time(self):
        if self.version in (2, 3):
            value = self._creation_time
        elif self.version >= 4:
            value = self._get_subpacket_values(
                C.CREATION_TIME_SUBPACKET_TYPE,
                'time')
        return datetime.datetime.fromtimestamp(value)

    def _set_creation_time(self, dt):
        # expiration time is relative to creation time, make sure it's kept in
        # sync with creation time.
        exp_time = self.signature__expiration_time
        value = time.mktime(dt.timetuple())
        if self.version in (2, 3):
            self._creation_time = value
        elif self.version >= 4:
            self._update_subpacket_values(
                C.CREATION_TIME_SUBPACKET_TYPE,
                'time', value)
        self.signature__expiration_time = exp_time

    creation_time = property(_get_creation_time, _set_creation_time)

    def _get_issuer_key_ids(self):
        if self.version in (2, 3):
            return [self._issuer_key_ids]
        elif self.version >= 4:
            return self._get_subpacket_values(
                C.ISSUER_KEY_ID_SUBPACKET_TYPE,
                'key_id', as_list=True)

    def _set_issuer_key_ids(self, key_ids):
        existing = self.issuer_key_ids
        if self.version in (2, 3) and len(key_ids) != 1:
            raise ValueError

        for k in set(key_ids) | set(existing):
            if k in existing and key_ids:
                continue
            elif k in existing:
                # Remove
                self._remove_subpacket_values(
                    C.ISSUER_KEY_ID_SUBPACKET_TYPE,
                    'key_id', k
                    )
            else:
                # Add
                self._add_subpacket_values(
                    C.ISSUER_KEY_ID_SUBPACKET_TYPE,
                    'key_id', k
                    )

    issuer_key_ids = property(_get_issuer_key_ids, _set_issuer_key_ids)

    def _get_signature_expiration_time(self):
        seconds = self._get_subpacket_values(
            C.EXPIRATION_SECONDS_SUBPACKET_TYPE,
            'time')
        # "If this is not present or has a value of zero, the key never
        #  expires."
        if not seconds:
            return None
        return self.creation_time + datetime.timedelta(seconds=seconds)

    def _set_signature_expiration_time(self, dt):
        if dt is None:
            value = 0
        elif dt < self.creation_time:
            raise ValueError
        else:
            td = dt - self.creation_time
            value = td.seconds + td.days * 86400
            self._update_subpacket_values(
                C.EXPIRATION_SECONDS_SUBPACKET_TYPE,
                'time', value)

    signature_expiration_time = property(
        _get_signature_expiration_time,
        _set_signature_expiration_time)

    def _get_exportable(self):
        return self._get_subpacket_values(
            C.EXPORTABLE_SUBPACKET_TYPE,
            'exportable')

    def _set_exportable(self, value):
        self._update_subpacket_values(
            C.EXPORTABLE_SUBPACKET_TYPE,
            'exportable', value)

    exportable = property(_get_exportable, _set_exportable)

    def _get_trust_amount(self):
        return self._get_subpacket_values(
            C.TRUST_SUBPACKET_TYPE,
            'trust_amount')

    def _set_trust_amount(self, value):
        self._update_subpacket_values(
            C.TRUST_SUBPACKET_TYPE,
            'trust_amount', value)

    trust_amount = property(_get_trust_amount, _set_trust_amount)

    def _get_trust_depth(self):
        return self._get_subpacket_values(
            C.TRUST_SUBPACKET_TYPE,
            'trust_depth')

    def _set_trust_depth(self, value):
        self._update_subpacket_values(
            C.TRUST_SUBPACKET_TYPE,
            'trust_depth', value)

    trust_depth = property(_get_trust_depth, _set_trust_depth)

    def _get_regular_expressions(self):
        patterns = self._get_subpacket_values(
            C.REGULAR_EXPRESSION_SUBPACKET_TYPE,
            'pattern', as_list=True)
        regexes = [re.compile(pattern) for pattern in patterns]
        return regexes

    def _set_regular_expressions(self, regexes):
        existing = [regex.pattern for regex in self.regular_expressions]
        regexes = [regex.pattern for regex in regexes]

        for k in set(regexes) | set(existing):
            if k in existing and regexes:
                continue
            elif k in existing:
                # Remove
                self._remove_subpacket_values(
                    C.REGULAR_EXPRESSION_SUBPACKET_TYPE,
                    'pattern', k
                    )
            else:
                # Add
                self._add_subpacket_values(
                    C.REGULAR_EXPRESSION_SUBPACKET_TYPE,
                    'pattern', k
                    )

    regular_expressions = property(_get_regular_expressions,
                                   _set_regular_expressions)

    def _get_revocable(self):
        return self._get_subpacket_values(
            C.REVOCABLE_SUBPACKET_TYPE,
            'revocable')

    def _set_revocable(self, value):
        self._update_subpacket_values(
            C.REVOCABLE_SUBPACKET_TYPE,
            'revocable', value)

    revocable = property(_get_exportable, _set_exportable)

    def _get_notations(self):
        subpackets = self._get_subpackets(C.NOTATION_SUBPACKET_TYPE)
        return [
            self.NotationClass.from_subpacket(s)
            for s in subpackets
        ]

    def _set_notations(self, notations):
        existing = self.notations

        for k in set(notations) | set(existing):
            if k in existing and notations:
                continue
            elif k in existing:
                # Remove
                self._remove_subpacket(
                    k.to_subpacket()
                    )
            else:
                # Add
                self._add_subpacket(
                    k.to_subpacket()
                    )

    notations = property(_get_notations, _set_notations)

    def _get_issuer_user_id(self):
        return self._get_subpacket_values(
            C.ISSUERS_USER_ID_SUBPACKET_TYPE,
            'user_id')

    def _set_issuer_user_id(self, value):
        self._update_subpacket_values(
            C.ISSUERS_USER_ID_SUBPACKET_TYPE,
            'user_id', value)

    issuer_user_id = property(_get_issuer_user_id, _set_issuer_user_id)

    def _get_revocation_reason(self):
        return self._get_subpacket_values(
            C.TRUST_SUBPACKET_TYPE,
            'revocation_reason')

    def _set_revocation_reason(self, value):
        self._update_subpacket_values(
            C.TRUST_SUBPACKET_TYPE,
            'trust_amount', value)

    revocation_reason = property(_get_revocation_reason,
                                 _set_revocation_reason)

    def _get_revocation_code(self):
        return self._get_subpacket_values(
            C.REVOCATION_REASON_SUBPACKET_TYPE,
            'revocation_code')

    def _set_revocation_code(self, value):
        self._update_subpacket_values(
            C.REVOCATION_REASON_SUBPACKET_TYPE,
            'revocation_code', value)

    revocation_code = property(_get_revocation_code, _set_revocation_code)

    def _get_embedded_signatures(self):
        subpackets = self._get_subpackets(C.EMBEDDED_SIGNATURE_SUBPACKET_TYPE)
        return [
            self.__class__.from_packet(s.signature, self)
            for s in subpackets
        ]

    def _set_embedded_signatures(self, embedded_signatures):
        existing = self.embedded_signatures

        for k in set(embedded_signatures) | set(existing):
            if k in existing and embedded_signatures:
                continue
            elif k in existing:
                # Remove
                self._remove_subpacket(
                    k.to_packet().to_embedded_subpacket()
                    )
            else:
                # Add
                self._add_subpacket(
                    k.to_packet().to_embedded_subpacket()
                    )

    embedded_signatures = property(_get_embedded_signatures,
                                   _set_embedded_signatures)

    def _get_key_expiration_time(self):
        seconds = self._get_subpacket_values(
            C.KEY_EXPIRATION_TIME_SUBPACKET_TYPE,
            'time')
        # "If this is not present or has a value of zero, the key never
        #  expires."
        if not seconds:  # 0 or None
            return seconds
        return self.target.creation_time + datetime.timedelta(seconds=seconds)

    def _set_key_expiration_time(self, value):
        delta = value - self.target.creation_time
        seconds = delta.days * 86400 + delta.seconds
        self._update_subpacket_values(
            C.KEY_EXPIRATION_TIME_SUBPACKET_TYPE,
            'time', seconds)

    key_expiration_time = property(_get_key_expiration_time,
                                   _set_key_expiration_time)

    def _get_preferred_compression_algorithms(self):
        return self._get_subpacket_values(
            C.PREFERRED_COMPRESSION_ALGORITHMS_SUBPACKET_TYPE,
            'preferred_algorithms')

    def _set_preferred_compression_algorithms(self, value):
        self._update_subpacket_values(
            C.PREFERRED_COMPRESSION_ALGORITHMS_SUBPACKET_TYPE,
            'preferred_algorithms', value)

    preferred_compression_algorithms = property(
        _get_preferred_compression_algorithms,
        _set_preferred_compression_algorithms)

    def _get_preferred_hash_algorithms(self):
        return self._get_subpacket_values(
            C.PREFERRED_HASH_ALGORITHMS_SUBPACKET_TYPE,
            'preferred_algorithms')

    def _set_preferred_hash_algorithms(self, value):
        self._update_subpacket_values(
            C.PREFERRED_HASH_ALGORITHMS_SUBPACKET_TYPE,
            'preferred_algorithms', value)

    preferred_hash_algorithms = property(
        _get_preferred_hash_algorithms,
        _set_preferred_hash_algorithms)

    def _get_preferred_symmetric_algorithms(self):
        return self._get_subpacket_values(
            C.PREFERRED_SYMMETRIC_ALGORITHMS_SUBPACKET_TYPE,
            'preferred_algorithms')

    def _set_preferred_symmetric_algorithms(self, value):
        self._update_subpacket_values(
            C.PREFERRED_SYMMETRIC_ALGORITHMS_SUBPACKET_TYPE,
            'preferred_algorithms', value)

    preferred_symmetric_algorithms = property(
        _get_preferred_symmetric_algorithms,
        _set_preferred_symmetric_algorithms)

    def _get_revocation_keys(self):
        subpackets = self._get_subpackets(C.REVOCATION_KEY_SUBPACKET_TYPE)
        return [
            self.RevocationKeyInfoClass.from_subpacket(s)
            for s in subpackets
        ]

    def _set_revocation_keys(self, revocation_keys):
        existing = self.revocation_keys

        for k in set(revocation_keys) | set(existing):
            if k in existing and revocation_keys:
                continue
            elif k in existing:
                # Remove
                self._remove_subpacket(
                    k.to_subpacket()
                    )
            else:
                # Add
                self._add_subpacket(
                    k.to_subpacket()
                    )

    revocation_keys = property(_get_revocation_keys, _set_revocation_keys)

    def _get_key_server_should_not_modify(self):
        return self._get_subpacket_values(
            C.KEY_SERVER_PREFERENCES_SUBPACKET_TYPE,
            'no_modify')

    def _set_key_server_should_not_modify(self, value):
        self._update_subpacket_values(
            C.KEY_SERVER_PREFERENCES_SUBPACKET_TYPE,
            'no_modify', value)

    key_server_should_not_modify = property(
        _get_key_server_should_not_modify, _set_key_server_should_not_modify)

    def _get_preferred_key_server(self):
        return self._get_subpacket_values(
            C.PREFERRED_KEY_SERVER_SUBPACKET_TYPE,
            'uri')

    def _set_preferred_key_server(self, value):
        self._update_subpacket_values(
            C.PREFERRED_KEY_SERVER_SUBPACKET_TYPE,
            'uri', value)

    preferred_key_server = property(
        _get_preferred_key_server, _set_preferred_key_server)

    def _get_primary_user_id(self):
        return self._get_subpacket_values(
            C.PRIMARY_USER_ID_SUBPACKET_TYPE,
            'primary')

    def _set_primary_user_id(self, value):
        self._update_subpacket_values(
            C.PRIMARY_USER_ID_SUBPACKET_TYPE,
            'primary', value)

    primary_user_id = property(
        _get_primary_user_id, _set_primary_user_id)

    def _get_policy_uri(self):
        return self._get_subpacket_values(
            C.POLICY_URI_SUBPACKET_TYPE,
            'uri')

    def _set_policy_uri(self, value):
        self._update_subpacket_values(
            C.POLICY_URI_SUBPACKET_TYPE,
            'uri', value)

    policy_uri = property(_get_policy_uri, _set_policy_uri)

    def _get_supports_modification_detection(self):
        return self._get_subpacket_values(
            C.FEATURES_SUBPACKET_TYPE,
            'supports_modification_detection')

    def _set_supports_modification_detection(self, value):
        self._update_subpacket_values(
            C.FEATURES_SUBPACKET_TYPE,
            'supports_modification_detection', value)

    supports_modification_detection = property(
        _get_supports_modification_detection,
        _set_supports_modification_detection)

    def _get_may_certify_others(self):
        return self._get_subpacket_values(
            C.KEY_FLAGS_SUBPACKET_TYPE,
            'may_certify_others')

    def _set_may_certify_others(self, value):
        self._update_subpacket_values(
            C.KEY_FLAGS_SUBPACKET_TYPE,
            'may_certify_others', value)

    may_certify_others = property(
        _get_may_certify_others, _set_may_certify_others)

    def _get_may_sign_data(self):
        return self._get_subpacket_values(
            C.KEY_FLAGS_SUBPACKET_TYPE,
            'may_sign_data')

    def _set_may_sign_data(self, value):
        self._update_subpacket_values(
            C.KEY_FLAGS_SUBPACKET_TYPE,
            'may_sign_data', value)

    may_sign_data = property(
        _get_may_sign_data, _set_may_sign_data)

    def _get_may_encrypt_comms(self):
        return self._get_subpacket_values(
            C.KEY_FLAGS_SUBPACKET_TYPE,
            'may_encrypt_comms')

    def _set_may_encrypt_comms(self, value):
        self._update_subpacket_values(
            C.KEY_FLAGS_SUBPACKET_TYPE,
            'may_encrypt_comms', value)

    may_encrypt_comms = property(
        _get_may_encrypt_comms, _set_may_encrypt_comms)

    def _get_may_encrypt_storage(self):
        return self._get_subpacket_values(
            C.KEY_FLAGS_SUBPACKET_TYPE,
            'may_encrypt_storage')

    def _set_may_encrypt_storage(self, value):
        self._update_subpacket_values(
            C.KEY_FLAGS_SUBPACKET_TYPE,
            'may_encrypt_storage', value)

    may_encrypt_storage = property(
        _get_may_encrypt_storage, _set_may_encrypt_storage)

    def _get_may_be_used_for_auth(self):
        return self._get_subpacket_values(
            C.KEY_FLAGS_SUBPACKET_TYPE,
            'may_be_used_for_auth')

    def _set_may_be_used_for_auth(self, value):
        self._update_subpacket_values(
            C.KEY_FLAGS_SUBPACKET_TYPE,
            'may_be_used_for_auth', value)

    may_be_used_for_auth = property(
        _get_may_be_used_for_auth, _set_may_be_used_for_auth)

    def _get_may_have_been_split(self):
        return self._get_subpacket_values(
            C.KEY_FLAGS_SUBPACKET_TYPE,
            'may_have_been_split')

    def _set_may_have_been_split(self, value):
        self._update_subpacket_values(
            C.KEY_FLAGS_SUBPACKET_TYPE,
            'may_have_been_split', value)

    may_have_been_split = property(
        _get_may_have_been_split, _set_may_have_been_split)

    def _get_may_have_multiple_owners(self):
        return self._get_subpacket_values(
            C.KEY_FLAGS_SUBPACKET_TYPE,
            'may_have_multiple_owners')

    def _set_may_have_multiple_owners(self, value):
        self._update_subpacket_values(
            C.KEY_FLAGS_SUBPACKET_TYPE,
            'may_have_multiple_owners', value)

    may_have_multiple_owners = property(
        _get_may_have_multiple_owners, _set_may_have_multiple_owners)

    @property
    def parent(self):
        return self._target_ref()

    @property
    def revocation(self):
        return self.signature_type in (
            C.CERTIFICATION_REVOCATION_SIGNATURE,
            C.KEY_REVOCATION_SIGNATURE,
            C.SUBKEY_REVOCATION_SIGNATURE)

    @property
    def target(self):
        parent = self.parent
        # get target subpacket
        subpackets = self._get_subpackets(C.TARGET_SUBPACKET_TYPE)
        for sub in subpackets:
            expected_digest = sub.hash
            hash_algorithm = sub.hash_algorithm
            pub_algorithm = sub.public_key_algorithm
            for sig in parent.signatures:
                digest = utils.hash_packet_for_signature(
                    sig.to_packet(), self.signature_type,
                    self.signature_version,
                    hash_algorithm,
                    self.creation_time,
                    pub_algorithm,
                    )
                if digest == expected_digest:
                    return sig

        # Fallback
        revocable = []
        for sig in parent.signatures:
            if sig is self:
                continue
            if set(self.issuer_key_ids) & set(sig.issuer_key_ids):
                revocable.append(sig)
        if len(revocable) == 1:
            return revocable[0]

    @property
    def expired(self):
        if self.signature_expiration_time:
            return self.get_current_time() > self.signature_expiration_time
        return False

    @property
    def revoked(self):
        if self.signature_type in (
                C.SIGNATURE_DIRECTLY_ON_A_KEY,
                C.SUBKEY_BINDING_SIGNATURE,
                C.GENERIC_CERTIFICATION,
                C.CASUAL_CERTIFICATION,
                C.PERSONA_CERTIFICATION,
                C.POSITIVE_CERTIFICATION,
                ):
            if not self.parent:
                return None
            for s in self.parent.signatures:
                if s.revocation and s.target == self:
                    return True
        return False

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
