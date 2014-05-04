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

"""Utility functions for creating keys and packets for test purposes.
To test all our code branches, we need to create some quite deformed
keys.
"""

import math
import time

from Crypto import Random
from Crypto.Hash import MD5
from Crypto.Hash import SHA
from Crypto.PublicKey import DSA
from Crypto.PublicKey import ElGamal
from Crypto.PublicKey import RSA
from Crypto.Util.number import bytes_to_long

from pgp import utils


TEST_ELG_K = bytes_to_long(
    b'+|\xb2\x9e\xd5\x83o\xd0\xa4.D\xbfy\x1d\xa6\xeax\xe7\x1b\xc1\x92\x81)w'
    b'\xf0\xa0 \x00\xdd7\xebH\r\xe2`G\x9d\x10Z\xb4*\xf3+w\x03\xa7\xa9tP\xaa'
    b'\xc7\x1f\x11\xc5\x1f5`\x80\xec\x9c\xbf\xfeg\xc8\xd7|4\xd3\xd3\xdb\n\xd5'
    b'J\xf7:\x8a\x99\x11\x9ciN\x8d\xbaV\xab\x9d\x8e;\xf4\xaa\xad\xd2\xd5H\xc1'
    b'\x91v\x0c\xe1\x10\x959\x00BD\xf6\xa4\x02\xa4\xbb-\xad+x\xa21\xc6\x82'
    b'\xfesQ\xce\xbb\xe4W\x02\xea\xdd'
    )
"""This is a precalculated value of K for ElGamal signing when we don't
care about security - like in testing. Since the minimum ELG size is
1024, we can use this for all key sizes.
"""


def make_key_objects(pub_algorithm_type, key_size):
    if pub_algorithm_type == 17:
        secret_key = DSA.generate(key_size)
    elif pub_algorithm_type in (1, 3):
        secret_key = RSA.generate(key_size)
    elif pub_algorithm_type == 20:
        # TODO: This should not be allowed except for testing purposes.
        # XXX: This can take a really long time
        secret_key = ElGamal.generate(key_size, Random.new().read)
    else:
        # TODO: complete
        raise ValueError

    public_key = secret_key.publickey()
    return secret_key, public_key


def make_key(user_id, pub_algorithm_type, key_size):
    """Returns a tuple of a bytearray representing the transferrable
    public key and the secret key object.
    """

    secret_key, public_key = make_key_objects(pub_algorithm_type, key_size)
    packets = []

    public_key_packet = make_public_key_packet(4, int(time.time()), 0,
                                               public_key, pub_algorithm_type)
    packets.append(public_key_packet)

    user_id_packet = make_user_id_packet(4, user_id)
    packets.append(user_id_packet)
    user_id_selfsig_subpackets = [
        make_creation_time_subpacket(int(time.time())),
        make_expiration_time_subpacket(0),
        make_issuer_key_subpacket(public_key_packet['key_id']),
        ]
    user_id_selfsig = make_signature_packet(
                            secret_key, public_key_packet, user_id_packet, 4,
                            0x10, pub_algorithm_type, 8,
                            subpackets=user_id_selfsig_subpackets)
    packets.append(user_id_selfsig)

    result = bytearray()
    for packet in packets:
        result.extend(packet_to_bytes(packet))
    return result, secret_key


def make_signature_subpacket(type_, data, critical=False, hashed=True):
    return {'type': type_,
            'critical': critical,
            'hashed': hashed,
            'data': data}


def make_creation_time_subpacket(t, critical=False, hashed=True):
    data = utils.int_to_4byte(t)
    return make_signature_subpacket(2, data, critical, hashed)


def make_expiration_time_subpacket(t, critical=False, hashed=True):
    data = utils.int_to_4byte(t)
    return make_signature_subpacket(3, data, critical, hashed)


def make_exportable_subpacket(bool_, critical=False, hashed=True):
    data = bytearray([int(bool_)])
    return make_signature_subpacket(4, data, critical, hashed)


def make_trust_signature_subpacket(depth, amount, critical=False,
                                   hashed=True):
    data = bytearray([depth, amount])
    return make_signature_subpacket(5, data, critical, hashed)


def make_regex_subpacket(regex, critical=False, hashed=True):
    data = bytearray(regex.encode('ascii'))
    data.append(0x00)
    return make_signature_subpacket(6, data, critical, hashed)


def make_revocable_subpacket(bool_, critical=False, hashed=True):
    data = bytearray([int(bool_)])
    return make_signature_subpacket(7, data, critical, hashed)


def make_key_expiration_time_subpacket(t, critical=False, hashed=True):
    data = utils.int_to_4byte(t)
    return make_signature_subpacket(9, data, critical, hashed)


def make_preferred_sym_algorithms_subpacket(types, critical=False,
                                            hashed=True):
    data = bytearray(types)
    return make_signature_subpacket(11, data, critical, hashed)


def make_revocation_key_subpacket(fingerprint, pub_algorithm_type,
                                  sensitive=False, critical=False,
                                  hashed=True):
    data = bytearray([0x80 + (0x40 if sensitive else 0x00),
                      pub_algorithm_type])
    data.extend(utils.hex_to_bytes(fingerprint, 20))
    return make_signature_subpacket(12, data, critical, hashed)


def make_issuer_key_subpacket(key_id, critical=False, hashed=True):
    data = utils.hex_to_bytes(key_id, 8)
    return make_signature_subpacket(16, data, critical, hashed)


def make_notation_subpacket(namespace, name, value, is_text, critical=False,
                            hashed=True):
    data = bytearray([
            0x80 if is_text else 0x00,
            0x00,
            0x00,
            0x00
            ])
    name_with_namespace = u'{0}@{1}'.format(name, namespace)
    value_bytes = value
    if is_text:
        value_bytes = value.encode('utf8')
    name_with_namespace_bytes = name_with_namespace.encode('utf8')
    data.extend(utils.int_to_2byte(len(name_with_namespace_bytes)))
    data.extend(utils.int_to_2byte(len(value_bytes)))
    data.extend(bytearray(name_with_namespace_bytes))
    data.extend(bytearray(value_bytes))
    return make_signature_subpacket(20, data, critical, hashed)


def make_preferred_hash_algorithms_subpacket(types, critical=False,
                                             hashed=True):
    data = bytearray(types)
    return make_signature_subpacket(21, data, critical, hashed)


def make_preferred_compression_algorithms_subpacket(types, critical=False,
                                                    hashed=True):
    data = bytearray(types)
    return make_signature_subpacket(22, data, critical, hashed)


def make_key_server_prefs_subpacket(no_modify, critical=False, hashed=True):
    data = bytearray([0x80 if no_modify else 0x00])
    return make_signature_subpacket(23, data, critical, hashed)


def make_preferred_key_server_subpacket(uri, critical=False, hashed=True):
    data = bytearray(uri.encode('utf8'))
    return make_signature_subpacket(24, data, critical, hashed)


def make_primary_user_id_subpacket(primary, critical=False, hashed=True):
    data = bytearray([int(primary)])
    return make_signature_subpacket(25, data, critical, hashed)


def make_policy_uri_subpacket(uri, critical=False, hashed=True):
    data = bytearray(uri.encode('utf8'))
    return make_signature_subpacket(26, data, critical, hashed)


def make_flags_subpacket(may_certify, may_sign, may_encrypt_comms,
                         may_encrypt_storage, may_have_been_split,
                         may_be_used_for_auth, may_be_shared, critical=False,
                         hashed=True):
    data = bytearray([
            (0x01 if may_certify else 0x00) +
            (0x02 if may_sign else 0x00) +
            (0x04 if may_encrypt_comms else 0x00) +
            (0x08 if may_encrypt_storage else 0x00) +
            (0x10 if may_have_been_split else 0x00) +
            (0x20 if may_be_used_for_auth else 0x00) +
            (0x80 if may_be_shared else 0x00)
            ])
    return make_signature_subpacket(27, data, critical, hashed)


def make_user_id_subpacket(user_id, critical=False, hashed=True):
    data = bytearray(user_id.encode('utf8'))
    return make_signature_subpacket(28, data, critical, hashed)


def make_revocation_reason_subpacket(revocation_code, revocation_string,
                                     critical=False, hashed=True):
    data = bytearray([revocation_code])
    data.extend(revocation_string.encode('utf8'))
    return make_signature_subpacket(29, data, critical, hashed)


def make_features_subpacket(supports_modification_detection, critical=False,
                            hashed=True):
    data = bytearray([
            0x01 if supports_modification_detection else 0x00
            ])
    return make_signature_subpacket(30, data, critical, hashed)


def make_target_subpacket(pub_algorithm_type, hash_algorithm_type, digest,
                          critical=False, hashed=True):
    data = bytearray([pub_algorithm_type, hash_algorithm_type])
    data.extend(digest)
    return make_signature_subpacket(31, data, critical, hashed)


def make_embedded_signature_subpacket(signature, critical=False, hashed=True):
    data = signature_to_bytes(signature)
    return make_signature_subpacket(32, data, critical, hashed)


def make_signature_packet(secret_key, public_key_packet, packet, version,
                          type_, pub_algorithm_type, hash_algorithm_type,
                          creation_time=None, expiration_time=None,
                          key_id=None, subpackets=None):
    subpackets = subpackets or []
    signature = {
        'type': 2,
        'version': version,
        'sig_version': version,
        'sig_type': type_,
        'pub_algorithm_type': pub_algorithm_type,
        'hash_algorithm_type': hash_algorithm_type,
        'subpackets': subpackets
        }

    hashed_subpacket_data = bytearray()
    if version in (2, 3):
        if None in (creation_time, key_id):
            raise TypeError(
                    'Creation time and key ID must be provided for version 3 '
                    'signatures.')
        signature['creation_time'] = creation_time
        signature['key_id'] = key_id
    elif version >= 4:
        if (creation_time, key_id) != (None, None):
            raise TypeError(
                    'Version 4 signatures must store creation time and key '
                    'ID in subpackets.')
        for subpacket in subpackets:
            if subpacket['hashed']:
                hashed_subpacket_data.extend(subpacket_to_bytes(subpacket))

    hash_ = utils.hash_packet_for_signature(
                    packet_to_content_bytes(public_key_packet),
                    packet['type'],
                    packet_to_content_bytes(packet),
                    type_,
                    version,
                    hash_algorithm_type,
                    creation_time,
                    pub_algorithm_type,
                    hashed_subpacket_data
                )
    digest = bytearray(hash_.digest())
    signature['hash2'] = digest[:2]
    k = None
    if pub_algorithm_type == 20:
        k = TEST_ELG_K
    values = utils.sign_hash(pub_algorithm_type, secret_key, hash_, k=k)
    signature['values'] = values

    return signature


def subpacket_to_bytes(subpacket):
    data_len = len(subpacket['data']) + 1  # For the type
    result = bytearray()
    packet_length_bytes, _ = utils.new_packet_length_to_bytes(data_len, False)
    result.extend(packet_length_bytes)
    raw = subpacket['type'] + (0x80 if subpacket['critical'] else 0x00)
    result.append(raw)
    result.extend(subpacket['data'])
    return result


def signature_to_bytes(signature):
    result = bytearray()
    sig_version = signature['sig_version']
    result.append(sig_version)
    if sig_version >= 4:
        result.append(signature['sig_type'])
        result.append(signature['pub_algorithm_type'])
        result.append(signature['hash_algorithm_type'])
        hashed_subpacket_data = bytearray()
        unhashed_subpacket_data = bytearray()
        for sp in signature['subpackets']:
            subpacket_data = subpacket_to_bytes(sp)
            if sp['hashed']:
                hashed_subpacket_data.extend(subpacket_data)
            else:
                unhashed_subpacket_data.extend(subpacket_data)

        result.extend(utils.int_to_2byte(len(hashed_subpacket_data)))
        result.extend(hashed_subpacket_data)
        result.extend(utils.int_to_2byte(len(unhashed_subpacket_data)))
        result.extend(unhashed_subpacket_data)

    elif sig_version in (2, 3):
        result.append(0x05)
        result.append(signature['sig_type'])
        result.extend(utils.int_to_4byte(signature['creation_time']))
        result.extend(signature['key_id'])
        result.append(signature['pub_algorithm_type'])
        result.append(signature['hash_algorithm_type'])

    result.extend(signature['hash2'])
    for value in signature['values']:
        if value is None:
            continue
        result.extend(utils.int_to_mpi(value))

    return result


def make_fingerprint(pubkey):
    # Derived from 'python-pgpdump'.
    # https://github.com/toofishes/python-pgpdump
    # Copyright (C) 2011-2014, Dan McGee.
    # All rights reserved.
    #
    # Derived from 'pgpdump'. http://www.mew.org/~kazu/proj/pgpdump/
    # Copyright (C) 1998, Kazuhiko Yamamoto.
    # All rights reserved.
    #
    # Redistribution and use in source and binary forms, with or without
    # modification, are permitted provided that the following conditions
    # are met:
    #
    # 1. Redistributions of source code must retain the above copyright
    #    notice, this list of conditions and the following disclaimer.
    # 2. Redistributions in binary form must reproduce the above copyright
    #    notice, this list of conditions and the following disclaimer in the
    #    documentation and/or other materials provided with the distribution.
    # 3. Neither the name of the author nor the names of its contributors
    #    may be used to endorse or promote products derived from this software
    #    without specific prior written permission.
    #
    # THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
    # ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
    # IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
    # PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE
    # LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
    # CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
    # SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
    # BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
    # WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
    # OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
    # IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
    if pubkey['version'] < 4:
        md5 = MD5.new()
        # Key type must be RSA for v2 and v3 public keys
        if pubkey['pub_algorithm_type'] in (1, 2, 3):
            key_id = ('%X' % pubkey['modulus'])[-8:].zfill(8)
            pubkey['key_id'] = key_id.encode('ascii')
            md5.update(utils.int_to_bytes(pubkey['modulus']))
            md5.update(utils.int_to_bytes(pubkey['exponent']))
        elif pubkey['pub_algorithm_type'] == 16:
            # Of course, there are ELG keys in the wild too. This formula
            # for calculating key_id and fingerprint is derived from an old
            # key and there is a test case based on it.
            key_id = ('%X' % pubkey['prime'])[-8:].zfill(8)
            pubkey['key_id'] = key_id.encode('ascii')
            md5.update(utils.int_to_bytes(pubkey['prime']))
            md5.update(utils.int_to_bytes(pubkey['group_gen']))
        fingerprint = md5.hexdigest().upper().encode('ascii')
    elif pubkey['version'] >= 4:
        sha1 = SHA.new()
        # TODO this is the same as hash_key
        pubkey_data = public_key_to_bytes(pubkey)
        pubkey_length = len(pubkey_data)
        seed_bytes = (0x99, (pubkey_length >> 8) & 0xff, pubkey_length & 0xff)
        sha1.update(bytearray(seed_bytes))
        sha1.update(pubkey_data)
        fingerprint = sha1.hexdigest().upper().encode('ascii')
    return fingerprint


def make_public_key_packet(version, creation_time, expiration_days,
                           public_key, pub_algorithm_type, instance=None):
    pubkey = instance or {
        'type': 6,
        'version': version,
        }
    pubkey['creation_time'] = creation_time
    pubkey['pub_algorithm_type'] = pub_algorithm_type
    if version in (2, 3):
        pubkey['expiration_days'] = expiration_days
        if pub_algorithm_type not in (1, 2, 3):
            raise ValueError(('Invalid algorithm type for version {0} '
                              'public key').format(version))

    if pub_algorithm_type in (1, 2, 3):
        pubkey['modulus'] = public_key.n
        pubkey['bitlen'] = \
            int(math.ceil(math.log(pubkey['modulus'], 2)))
        pubkey['exponent'] = public_key.e
    elif pub_algorithm_type == 17:
        pubkey['prime'] = public_key.p
        pubkey['bitlen'] = \
            int(math.ceil(math.log(pubkey['prime'], 2)))
        pubkey['group_order'] = public_key.q
        pubkey['group_gen'] = public_key.g
        pubkey['key_value'] = public_key.y
    elif pub_algorithm_type in (16, 20):
        pubkey['prime'] = public_key.p
        pubkey['bitlen'] = \
            int(math.ceil(math.log(pubkey['prime'], 2)))
        pubkey['group_gen'] = public_key.g
        pubkey['key_value'] = public_key.y

    pubkey['fingerprint'] = make_fingerprint(pubkey)
    pubkey['key_id'] = pubkey['fingerprint'][-16:]
    return pubkey


def public_key_to_bytes(pubkey):
    result = bytearray([pubkey['version']])
    result.extend(utils.int_to_4byte(pubkey['creation_time']))
    if pubkey['version'] in (2, 3):
        result.extend(utils.int_to_2byte(pubkey['expiration_days']))
    result.append(pubkey['pub_algorithm_type'])
    if pubkey['pub_algorithm_type'] in (1, 2, 3):
        result.extend(utils.int_to_mpi(pubkey['modulus']))
        result.extend(utils.int_to_mpi(pubkey['exponent']))
    elif pubkey['pub_algorithm_type'] == 17:
        result.extend(utils.int_to_mpi(pubkey['prime']))
        result.extend(utils.int_to_mpi(pubkey['group_order']))
        result.extend(utils.int_to_mpi(pubkey['group_gen']))
        result.extend(utils.int_to_mpi(pubkey['key_value']))
    elif pubkey['pub_algorithm_type'] in (16, 20):
        result.extend(utils.int_to_mpi(pubkey['prime']))
        result.extend(utils.int_to_mpi(pubkey['group_gen']))
        result.extend(utils.int_to_mpi(pubkey['key_value']))

    return result


def make_public_subkey_packet(version, creation_time, expiration_days,
                              public_key, pub_algorithm_type):
    subkey = {
        'type': 14,
        'version': version,
        }
    return make_public_key_packet(version, creation_time, expiration_days,
                                  public_key, pub_algorithm_type,
                                  instance=subkey)


def public_subkey_to_bytes(packet):
    return public_key_to_bytes(packet)


def packet_content_to_packet_bytes(version, type_, data):
    data_length = len(data)
    packet_type = type_
    tag = 0x80
    result = bytearray()
    if version >= 4:
        # "An implementation MAY use Partial Body Lengths for data packets, be
        #  they literal, compressed, or encrypted."
        remaining = data_length
        offset = 0
        while remaining:
            allow_partial = type_ in (8, 9, 11, 18)
            tag += 0x40 + packet_type
            result = bytearray([tag])
            packet_length_bytes, remaining = utils.new_packet_length_to_bytes(
                                            data_length,
                                            allow_partial)
            result.extend(packet_length_bytes)
            result.extend(data[offset:-remaining])
            offset = data_length - remaining

    else:
        tag += (packet_type << 2)
        result = bytearray([tag])
        result.extend(utils.old_packet_length_to_bytes(data_length))
        result.extend(data)

    return result


def make_user_id_packet(version, user_id):
    packet = {
        'type': 13,
        'version': version,
        }
    packet['user'] = user_id
    return packet


def user_id_to_bytes(packet):
    return bytearray(packet['user'].encode('utf8'))


def make_user_attribute_subpacket(image_data):
    subpacket = {}
    subpacket['subtype'] = 1
    subpacket['header_version'] = 1
    subpacket['header_length'] = 16
    subpacket['image_format'] = 1
    subpacket['image_data'] = image_data
    return subpacket


def make_user_attribute_packet(version, subpackets):
    packet = {
        'type': 17,
        'version': version,
        'subpackets': subpackets,
        }
    return packet


def user_attribute_subpacket_to_bytes(subpacket):
    # 0x10, 0x00 is the header length, little-endian
    result = bytearray([
            subpacket['header_length'] & 0xff,
            (subpacket['header_length'] >> 8) & 0xff,
            subpacket['header_version'],
            subpacket['image_format'],
        ])
    result.extend([0] * (subpacket['header_length'] - 4))
    result.extend(subpacket['image_data'])
    return result


def user_attribute_to_bytes(packet):
    result = bytearray()
    for subpacket in packet['subpackets']:
        sub_data = user_attribute_subpacket_to_bytes(subpacket)
        packet_length_bytes, _ = utils.new_packet_length_to_bytes(
                                    len(sub_data),
                                    allow_partial=False)
        result.extend(packet_length_bytes)
        result.append(subpacket['subtype'])
        result.extend(sub_data)

    return result


def packet_to_content_bytes(packet):
    if packet is None:
        return None
    if packet['type'] == 2:
        content = signature_to_bytes(packet)
    elif packet['type'] == 6:
        content = public_key_to_bytes(packet)
    elif packet['type'] == 13:
        content = user_id_to_bytes(packet)
    elif packet['type'] == 14:
        content = public_subkey_to_bytes(packet)
    elif packet['type'] == 17:
        content = user_attribute_to_bytes(packet)
    return content


def packet_to_bytes(packet):
    content = packet_to_content_bytes(packet)
    return packet_content_to_packet_bytes(
                packet['version'],
                packet['type'],
                content
            )
