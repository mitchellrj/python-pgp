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

from base64 import b64encode
import traceback
import sys

import magic
import pgpdump
from pgpdump.packet import new_tag_length
from pgpdump.utils import get_int2
from pgpdump.utils import get_int4
from pgpdump.utils import get_key_id

from pgp.exceptions import CannotParseCritical
from pgp.exceptions import CannotParseCriticalNotation
from pgp.exceptions import InvalidKeyPacketOrder
from pgp.exceptions import InvalidKeyPacketType
from pgp.exceptions import LocalCertificationSignature
from pgp.exceptions import RegexValueError
from pgp.exceptions import UnsupportedPacketType
from pgp.exceptions import UnsupportedSignatureVersion
from pgp.regex import validate_subpacket_regex
from pgp.utils import bytearray_to_hex
from pgp.utils import get_bitlen
from pgp.utils import hash_key_data


_marker = object()


def subpacket_type_to_keys(type_):
    return {
        2: ['creation_time'],
        3: ['expiration_seconds'],
        4: ['exportable'],
        5: ['trust_level', 'trust_amount'],
        6: ['regex'],
        7: ['revocable'],
        9: ['key_expiration_seconds'],
        11: ['preferred_sym_algorithms'],
        12: ['revocation_key'],
        21: ['preferred_hash_algorithms'],
        22: ['preferred_compression_algorithms'],
        23: ['key_server_no_modify'],
        24: ['preferred_key_server'],
        25: ['primary'],
        26: ['policy_uri'],
        27: ['may_certify_others', 'may_sign_data', 'may_encrypt_comms',
             'may_encrypt_storage', 'may_have_been_split',
             'may_be_used_for_auth', 'may_have_multiple_owners'],
        28: ['user_id'],
        29: ['revocation_code', 'revocation_reason'],
        30: ['supports_modification_detection'],
        31: ['target_pub_key_algorithm', 'target_hash_algorithm', 'target'],
    }.get(type_, None)


def parse_notation(data, hashed, encode_non_readable=b64encode):
    flags = get_int4(data, 0)

    notation_name_length = get_int2(data, 4)
    notation_value_length = get_int2(data, 6)
    name_end = 8 + notation_name_length
    value_end = name_end + notation_value_length

    notation_name = data[8:name_end].decode('utf8', 'replace')
    notation_name, notation_namespace = \
        (notation_name.split('@', 1) + [None])[:2]
    notation_value = data[name_end:value_end]

    if flags & 0xffffff:
        # None of these flags are defined. They MUST be zero.
        return None

    human_readable = (flags >> 24) & 0xff == 0x80
    if human_readable:
        # human readable
        notation_value = notation_value.decode('utf8', 'replace')
    else:
        notation_value = encode_non_readable(notation_value)

    return {
            u'name': notation_name,
            u'namespace': notation_namespace,
            u'human_readable': human_readable,
            u'value': notation_value,
            u'hashed': hashed,
        }


def parse_embedded_signature(data, hashed,
                             # For testing
                             PacketClass=pgpdump.packet.SignaturePacket,
                             parse_fn=None):

    parse_fn = parse_fn or parse_signature_packet
    name = pgpdump.packet.TAG_TYPES.get(2, 'Signature Subpacket')
    # We only get subpackets on new types so assume new is True
    subsignature_packet = \
        PacketClass(2, name, True, data)
    return parse_fn(subsignature_packet, 2, sig_hashed=hashed)


def parse_signature_subpacket(sub, signature, signature_owner_type,
                  signature_hashed=False,
                  # For testing
                  validate_subpacket_regex=validate_subpacket_regex,
                  parse_notation=parse_notation,
                  parse_embedded_signature=parse_embedded_signature):

    if sub.subtype == 2:
        if not sub.hashed:
            # "MUST be present in the hashed area."
            # Specification does not say what behavior should be if it
            # is present in the unhashed area. GnuPG & SKS ignore the
            # signature subpacket.
            return
        signature['creation_time'] = get_int4(sub.data, 0)
    elif sub.subtype == 3:
        # Raw expiration time is actually the time from the creation time
        # that expiration occurs in seconds, rather than a unix timestamp
        # as its name might imply
        exp_time = get_int4(sub.data, 0)
        if exp_time != 0:
            signature['expiration_seconds'] = exp_time
    elif sub.subtype == 4:
        exportable = bool(sub.data[0])
        if not exportable:
            # "Non-exportable, or "local", certifications are signatures
            #  made by a user to mark a key as valid within that user's
            #  implementation only."
            #
            # "[...]"
            #
            # "The receiver of a transported key "imports" it, and likewise
            #  trims any local certifications.  In normal operation, there
            #  won't be any, assuming the import is performed on an
            #  exported key.  However, there are instances where this can
            #  reasonably happen.  For example, if an implementation allows
            #  keys to be imported from a key database in addition to an
            #  exported key, then this situation can arise."
            #
            # "Some implementations do not represent the interest of a
            #  single user (for example, a key server).  Such
            #  implementations always trim local certifications from any
            #  key they handle."
            raise LocalCertificationSignature

        signature['exportable'] = exportable
    elif sub.subtype == 5:
        signature['trust_level'] = int(sub.data[0])
        signature['trust_amount'] = int(sub.data[1])
    elif sub.subtype == 6:
        # Null-terminated
        regex = sub.data[:-1].decode('ascii', 'replace')
        try:
            validate_subpacket_regex(regex)
        except RegexValueError:
            return
        signature.setdefault('regexes', [])
        # The specifcation doesn't cover it, but it is reasonable that a
        # signature might specify multiple regular expressions.
        #
        # "In most cases, an implementation SHOULD use the last subpacket
        #  in the signature, but MAY use any conflict resolution scheme
        #  that makes more sense."
        signature['regexes'].append({
                'regex': regex,
                'hashed': signature_hashed or sub.hashed
            })
    elif sub.subtype == 7:
        signature['revocable'] = bool(sub.data[0])
    elif sub.subtype == 9:
        # "This is found only on a self-signature."
        if not signature['selfsig']:
            return

        # Raw expiration time is actually the time from the creation time
        # that expiration occurs in seconds, rather than a unix timestamp
        # as its name might imply
        exp_time = get_int4(sub.data, 0)
        if exp_time == 0:
            return
        signature['key_expiration_seconds'] = exp_time
    elif sub.subtype == 11:
        # "This is found only on a self-signature."
        if not signature['selfsig']:
            return
        signature['preferred_sym_algorithms'] = list(map(int, sub.data))
    elif sub.subtype == 12:
        if not bool(sub.data[0] & 0x80):
            # 0x80 MUST be set
            return
        # If this sensitive key is included when we receive it, it must
        # be for a reason. It would not be exported to be given to us
        # otherwise.
        #
        # "If this flag is set, implementations SHOULD NOT export this
        #  signature to other users except in cases where the data needs
        #  to be available: when the signature is being sent to the
        #  designated revoker, or when it is accompanied by a revocation
        #  signature from that revoker."
        signature['revocation_key_sensitive'] = bool(sub.data[0] & 0x40)
        signature['revocation_key_pub_algorithm_type'] = sub.data[1]
        signature['revocation_key'] = \
            bytearray_to_hex(sub.data[2:])
    elif sub.subtype == 16:
        # "Some apparent conflicts may actually make sense -- for example,
        #  suppose a keyholder has a V3 key and a V4 key that share the
        #  same RSA key material.  Either of these keys can verify a
        #  signature created by the other, and it may be reasonable for a
        #  signature to contain an issuer subpacket for each key, as a way
        #  of explicitly tying those keys to the signature."
        signature.setdefault('key_ids', [])
        signature['key_ids'].append({
                'key_id': get_key_id(sub.data, 0).upper(),
                'hashed': signature_hashed or sub.hashed
                })
    elif sub.subtype == 20:
        notation = parse_notation(sub.data, signature_hashed or sub.hashed)
        if notation:
            if sub.critical:
                # "If there is a critical notation, the criticality
                #  applies to that specific notation and not to notations
                #  in general."
                raise CannotParseCriticalNotation(notation['name'])
            signature.setdefault('notations', [])
            signature['notations'].append(notation)

    elif sub.subtype == 21:
        # "This is found only on a self-signature."
        if not signature['selfsig']:
            return
        signature['preferred_hash_algorithms'] = list(map(int, sub.data))
    elif sub.subtype == 22:
        # "This is found only on a self-signature."
        if not signature['selfsig']:
            return
        signature['preferred_compression_algorithms'] = \
            list(map(int, sub.data))
    elif sub.subtype == 23:
        if not signature['selfsig']:
            # "This is found only on a self-signature."
            return
        # "All undefined flags MUST be zero."
        if sub.data[0] & 0x7f or any(sub.data[1:]):
            return

        signature['key_server_no_modify'] = bool(sub.data[0] & 0x80)
    elif sub.subtype == 24:
        signature['preferred_key_server'] = \
            sub.data.decode('utf8', 'replace')
    elif sub.subtype == 25:
        # "This is a flag in a User ID's self-signature"
        # ...
        # "there are two different and independent "primaries" -- one for
        #  User IDs, and one for User Attributes."
        if not signature['selfsig']:
            return
        if signature_owner_type not in (13, 17):
            return
        # Store the actual integer value. If we have multiple "primaries"
        # we can use this to resolve priority.
        #
        # "If more than one User ID in a key is marked as primary, the
        #  implementation may resolve the ambiguity in any way it sees
        #  fit, but it is RECOMMENDED that priority be given to the User
        #  ID with the most recent self-signature."
        signature['primary'] = int(sub.data[0])
    elif sub.subtype == 26:
        signature['policy_uri'] = sub.data.decode('utf8', 'replace')
    elif sub.subtype == 27:
        flags = sub.data[0]
        signature['may_certify_others'] = bool(flags & 0x01)
        signature['may_sign_data'] = bool(flags & 0x02)
        signature['may_encrypt_comms'] = bool(flags & 0x04)
        signature['may_encrypt_storage'] = bool(flags & 0x08)
        signature['may_be_used_for_auth'] = bool(flags & 0x20)
        # "The "split key" (0x10) and "group key" (0x80) flags are placed
        #  on a self-signature only; they are meaningless on a
        #  certification signature.  They SHOULD be placed only on a
        #  direct-key signature (type 0x1F) or a subkey signature
        #  (type 0x18), one that refers to the key the flag applies to."
        if signature['selfsig'] and signature['sig_type'] in (0x1f, 0x18):
            signature['may_have_been_split'] = bool(flags & 0x10)
            signature['may_have_multiple_owners'] = bool(flags & 0x80)
    elif sub.subtype == 28:
        signature['user_id'] = sub.data.decode('utf8', 'replace')
    elif sub.subtype == 29:
        # "This subpacket is used only in key revocation and certification
        #  revocation signatures."
        if signature['sig_type'] not in (0x20, 0x28):
            return
        revocation_code = int(sub.data[0])
        if (revocation_code in (0, 1, 2, 3, 32) or
            (revocation_code > 99 and revocation_code < 111)):
            signature['revocation_code'] = revocation_code
            signature['revocation_reason'] = \
                sub.data[1:].decode('utf8', 'replace')
    elif sub.subtype == 30:
        # "This subpacket is similar to a preferences subpacket, and only
        #  appears in a self-signature."
        if not signature['selfsig']:
            return
        if sub.data[0] & 0xfe:
            return
        if any(sub.data[1:]):
            return
        supports_modification = sub.data[0] & 0x01
        signature['supports_modification_detection'] = supports_modification
    elif sub.subtype == 31:
        signature['target_pub_key_algorithm'] = sub.data[0]
        signature['target_hash_algorithm'] = sub.data[1]
        # Store the target hash as hex
        signature['target_hash'] = bytearray_to_hex(sub.data[2:])
    elif sub.subtype == 32:
        subsignature = parse_embedded_signature(
                            sub.data, signature_hashed or sub.hashed)
        signature.setdefault('embedded_signatures', [])
        signature['embedded_signatures'].append(subsignature)

    # Unparseable signature subpackets
    # "If a subpacket is encountered that is marked critical but is
    #  unknown to the evaluating software, the evaluator SHOULD consider
    #  the signature to be in error."

    elif sub.subtype > 99 and sub.subtype < 111:
        # private / experimental
        if sub.critical:
            raise CannotParseCritical(sub.subtype)
    elif sub.subtype in (0, 1, 8, 13, 14, 15, 17, 18, 19):
        # "An implementation SHOULD ignore any subpacket of a type that it
        #  does not recognize."
        #raise ReservedSignatureSubpacket(sub.subtype)
        if sub.critical:
            raise CannotParseCritical(sub.subtype)
    else:
        # "An implementation SHOULD ignore any subpacket of a type that it
        #  does not recognize."
        #raise InvalidSignatureSubpacket(sub.subtype)
        if sub.critical:
            raise CannotParseCritical(sub.subtype)


def parse_signature_packet(p, parent_type, parent_key_ids=None,
                           sig_hashed=False,
                           # For testing
                           parse_signature_subpacket=parse_signature_subpacket
                           ):
    """Parse a single pgpdump signature packet into a Python dictionary
    of values. sig_hashed should be set to True for signature packets
    which are embedded as hashed signature subpackets.
    """

    signature = {}
    signature['validated'] = None
    signature['hash_algorithm_type'] = p.raw_hash_algorithm
    signature['pub_algorithm_type'] = p.raw_pub_algorithm
    signature['sig_type'] = p.raw_sig_type
    signature['sig_version'] = p.sig_version
    signature['hash2'] = bytearray_to_hex(p.hash2)

    # "If a subpacket is not hashed, then the information in it cannot be
    #  considered definitive because it is not part of the signature proper."
    #
    # For convenience, include the fields that are always hashed.
    signature['hashed'] = [
        'hash_algorithm_type',
        'pub_algorithm_type',
        'sig_type',
        'sig_version',
        ]

    if p.sig_version in (2, 3):
        # Only trust these explicitly if the version is < 4. If the version is
        # 4 or greater, these values may have come from unhashed subpackets
        # and could have been manipulated.

        signature['key_ids'] = [{
                'key_id': p.key_id.upper(),
                'hashed': True,
            }]
        signature['selfsig'] = p.key_id.upper() in parent_key_ids
        signature['creation_time'] = p.raw_creation_time
        signature['hashed'].extend([
                'creation_time',
            ])

    elif p.sig_version >= 4:
        hashed = {}

        # Parse Key IDs first so we know if it's a selfsignature or not
        for sub in p.subpackets:
            if sub.subtype == 16:
                parse_signature_subpacket(sub, signature, parent_type)

        sig_key_ids = set(map(
                lambda k: k['key_id'],
                signature.get('key_ids', [])
            ))
        signature['selfsig'] = bool(sig_key_ids & set(parent_key_ids))

        for sub in p.subpackets:
            if sub.subtype == 16:
                continue
            parse_signature_subpacket(sub, signature, parent_type)
            if sub.subtype not in (6, 16, 20, 32):
                hashed[sub.subtype] = sig_hashed or sub.hashed

        for k, v in hashed.items():
            if not k or not v:
                continue
            keys = subpacket_type_to_keys(k)
            signature['hashed'].extend(keys)
    else:
        raise UnsupportedSignatureVersion(p.sig_version)

    return signature


def skip_to_next_key(packet_generator):
    """Keep skipping packets from the stream until we get to the next
    public key packet, then return that and the number of packets we
    skipped.
    """

    skipped = 1
    try:
        packet = next(packet_generator)
        while packet.raw != 6:
            packet = next(packet_generator)
            skipped += 1
        return packet, skipped
    except StopIteration:
        return None, skipped
    except:
        packet, extra_skipped = skip_to_next_key(packet_generator)
        return packet, skipped + extra_skipped + 1


def parse_user_attribute_subpackets(p, parse_unknown=False):
    offset = 0
    while offset < len(p.data):
        sub_data = bytearray()
        sub_type = None
        sub_offset, sub_len, sub_partial = new_tag_length(p.data, offset)
        if sub_partial:
            # "An implementation MAY use Partial Body Lengths for data
            #  packets, be they literal, compressed, or encrypted.  [...]
            #  Partial Body Lengths MUST NOT be used for any other packet
            #  types."
            return
        sub_type = p.data[sub_offset]
        # + 1 for sub type
        sub_data_start = offset + sub_offset + 1
        sub_data_end = sub_data_start + sub_len
        sub_data.extend(p.data[sub_data_start:sub_data_end])
        offset = sub_data_end
        if sub_type == 0x01:
            # "The only currently defined subpacket type is 1, signifying
            #  an image."

            # "The first two octets of the image header contain the length of
            #  the image header.  Note that unlike other multi-octet numerical
            #  values in this document, due to a historical accident this
            #  value is encoded as a little-endian number."
            header_length = sub_data[0] + (sub_data[1] << 8)
            header_version = sub_data[2]
            if header_version == 1:
                if not header_length == 16:
                    continue
                image_format = sub_data[3]
                if any(sub_data[4:16]):
                    # Incorrect
                    continue
                if (image_format == 1 or
                    (image_format > 99 and image_format < 111)
                    ):
                    # "The only currently defined encoding format is the value
                    #  1 to indicate JPEG.  Image format types 100 through 110
                    #  are reserved for private or experimental use."
                    #
                    # "An implementation MAY try to determine the type of an
                    #  image by examination of the image data if it is unable
                    #  to handle a particular version of the image header or
                    #  if a specified encoding format value is not
                    #  recognized."
                    mime_type = magic.from_buffer(bytes(sub_data[16:1040]),
                                                  mime=True)
                    yield {
                            'sub_type': sub_type,
                            'content_data': sub_data[16:],
                            'mimetype': mime_type,
                        }
            elif parse_unknown:
                # If we want to parse unknown, non-image data
                content_data = sub_data[header_length:]
                mime_type = magic.from_buffer(bytes(content_data[:1024]),
                                              mime=True)
                yield {
                       'sub_type': sub_type,
                       'content_data': content_data,
                       'mimetype': mime_type,
                    }


def parse_key(packets,
              # For testing
              hash_key_data=hash_key_data,
              parse_signature_packet=parse_signature_packet,
              parse_user_attribute_subpackets=parse_user_attribute_subpackets,
              ):
    """Parse an iterable of PGPDump packets which make up a single
    public key.
    """

    key_hash = hash_key_data(packets)
    data = bytearray()
    signable = public_key = {'key_hash': key_hash}
    for p in packets:
        if p.raw == 2:  # 'Signature Packet'
            try:
                key_ids = [public_key['key_id'], signable.get('key_id')]
                signature = parse_signature_packet(p, signable['_raw_type'],
                                                   key_ids)
            except CannotParseCritical:
                # The signature is in error, but not the key
                signature = None
            except LocalCertificationSignature:
                signature = None
            if signature:
                signable.setdefault('signatures', [])
                signable['signatures'].append(signature)

        elif p.raw == 6:  # "Public Key Packet"
            public_key['_raw_type'] = 6
            public_key['key_id'] = p.key_id.upper()
            public_key['fingerprint'] = p.fingerprint
            public_key['creation_time'] = p.raw_creation_time
            public_key['expiration_days'] = p.raw_days_valid
            public_key['pub_algorithm_type'] = p.raw_pub_algorithm
            public_key['pubkey_version'] = p.pubkey_version

            # rsa vars
            public_key['modulus'] = p.modulus
            public_key['exponent'] = p.exponent

            # dsa & elg vars
            public_key['prime'] = p.prime
            public_key['group_order'] = p.group_order
            public_key['group_gen'] = p.group_gen
            public_key['key_value'] = p.key_value

            public_key['bitlen'] = get_bitlen(public_key)

            public_key['_data'] = p.original_data
            signable = public_key
        elif p.raw == 13:  # "User ID Packet":
            user_id_params = {}
            user_id_params['_raw_type'] = 13
            user_id_params['user_id'] = p.user
            user_id_params['_data'] = p.original_data
            public_key.setdefault('user_ids', [])
            public_key['user_ids'].append(user_id_params)
            signable = user_id_params
        elif p.raw == 14:  # 'Public Subkey Packet'
            subkey_params = {'parent': public_key}
            subkey_params['_data'] = p.original_data
            subkey_params['_raw_type'] = 14
            subkey_params['key_id'] = p.key_id.upper()
            subkey_params['fingerprint'] = p.fingerprint
            subkey_params['creation_time'] = p.raw_creation_time
            subkey_params['expiration_days'] = p.raw_days_valid
            subkey_params['pub_algorithm_type'] = p.raw_pub_algorithm
            subkey_params['pubkey_version'] = p.pubkey_version
            # rsa vars
            subkey_params['modulus'] = p.modulus
            subkey_params['exponent'] = p.exponent
            # dsa & elg vars
            subkey_params['prime'] = p.prime
            subkey_params['group_order'] = p.group_order
            subkey_params['group_gen'] = p.group_gen
            subkey_params['key_value'] = p.key_value
            subkey_params['bitlen'] = get_bitlen(subkey_params)
            public_key.setdefault('subkeys', [])
            public_key['subkeys'].append(subkey_params)
            signable = subkey_params
        elif p.raw == 17:  # 'User Attribute Packet'
            public_key.setdefault('user_attributes', [])
            user_attribute = {
                    '_data': p.original_data,
                    '_raw_type': 17,
                    }

            # PGPDump's parsing is not sufficient here. It only parses the last
            # subpacket
            user_attribute['subpackets'] = list(
                    parse_user_attribute_subpackets(p)
                )

            public_key['user_attributes'].append(user_attribute)
            signable = user_attribute
        else:
            raise UnsupportedPacketType(p.raw)

        data += p.original_data

    public_key['data'] = data
    return public_key


def validate_transferrable_public_key(packets):
    # http://tools.ietf.org/html/rfc4880#section-11.1

    type_order = list(map(lambda p: p.raw, packets))
    previous = None
    if packets[0].raw != 6:
        raise InvalidKeyPacketOrder("The first packet must be a Public Key "
                                    "Packet")
    pubkey_version = packets[0].pubkey_version
    for i in range(len(type_order)):
        if i > 0:
            previous = type_order[i - 1]
        this = type_order[i]
        if this == 6:
            if i != 0:
                raise InvalidKeyPacketOrder("Public Key Packet must be first "
                                            "in the list")
        elif this == 2:
            sig_type = packets[i].sig_type
            previous_non_sig = [x for x in type_order[i - 1::-1] if x != 2][0]
            if sig_type == 0x1f:
                for t in type_order[:i]:
                    if t not in (6, 2):
                        raise InvalidKeyPacketOrder(
                                    "Signature Directly On Key may only "
                                    "appear immediately after the Public Key "
                                    "Packet")
            elif sig_type == 0x18:
                if previous != 14:
                    raise InvalidKeyPacketOrder(
                                "Subkey Binding Signature may only appear "
                                "immediately after a Subkey Packet")
            elif sig_type == 0x20:
                for t in type_order[:i]:
                    if t not in (6, 2):
                        raise InvalidKeyPacketOrder(
                                    "Key Revocation Signature may only "
                                    "appear immediately after the Public Key "
                                    "Packet and other Signatures Directly On "
                                    "Key")
            elif sig_type == 0x28:
                if previous != 2 or packets[i - 1].sig_type != 0x18:
                    raise InvalidKeyPacketOrder(
                                "Subkey Revocation Signature may only appear "
                                "after a Subkey Binding Signature")
            elif sig_type in (0x10, 0x11, 0x12, 0x13):
                if previous_non_sig not in (13, 17):
                    raise InvalidKeyPacketOrder(
                                "Certifications must apply to user IDs or "
                                "user attributes")
            else:
                raise InvalidKeyPacketType(
                            "Invalid signature type for transferrable "
                            "public key")
        elif this == 13:
            for t in type_order[:i]:
                if t not in (6, 2, 13):
                    raise InvalidKeyPacketOrder(
                                "User IDs must appear before all user "
                                "attributes and subkeys")
        elif this == 17:
            for t in type_order[:i]:
                if t not in (6, 2, 13, 17):
                    raise InvalidKeyPacketOrder(
                                "User attributes must appear before all "
                                "subkeys")
        elif this == 14:
            if pubkey_version < 4:
                raise InvalidKeyPacketType("V3 keys may not contain subkeys")
            if type_order[i + 1] != 2 or packets[i + 1].sig_type != 0x18:
                raise InvalidKeyPacketOrder(
                            "Subkeys must be followed by a binding signature")
        else:
            raise InvalidKeyPacketType()


def parse(parser,
          # For testing
          skip_to_next_key=skip_to_next_key,
          validate_transferrable_public_key=validate_transferrable_public_key,
          parse_key_packets=parse_key,
          err_stream=sys.stderr):
    """Parse a stream of PGPDump packets."""

    packets = parser.packets()
    key_packets = []
    packet = next(packets)
    i = 0
    try:
        while True:
            try:
                next_packet = next(packets)
            except StopIteration:
                raise
            except Exception:
                tb = traceback.format_exception(*sys.exc_info())
                i += 1
                packet, skipped = skip_to_next_key(packets)
                err_stream.write((
                    u"Error loading key {0}. Skipped {1} packets.\n"
                    ).format(i, skipped))
                err_stream.write(u'Original exception:\n')
                err_stream.write(u'\n'.join(tb[1:]) + '\n')
                if packet is None:
                    # end of the stream, re-raise StopIteration
                    next(packets)
                key_packets = [packet]
                continue
            key_packets.append(packet)
            if next_packet.raw == 6:
                i += 1
                validate_transferrable_public_key(key_packets)
                yield parse_key_packets(key_packets)
                key_packets = []
            packet = next_packet
    except StopIteration:
        if packet:
            key_packets.append(packet)
            validate_transferrable_public_key(key_packets)
            yield parse_key_packets(key_packets)
