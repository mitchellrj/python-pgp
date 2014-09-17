# python-pgp A Python OpenPGP implementation
# Copyright (C) 2014 Richard Mitchell
#
# Portions of this file are based on code from SKS.
# SKS is Copyright (C) 2002, 2003, 2004, 2005, 2006, 2007, 2008, 2009, 2010,
#                      2011, 2012, 2013  Yaron Minsky and Contributors
# SKS is licensed under the GNU Public License version 2 or later.
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

from collections import OrderedDict

from pgp import utils


def keys_equivalent(key1, key2):
    return (
        key1.version == key2.version
        and key1.public_key_algorithm == key2.public_key_algorithm
        and key1.modulus_n == key2.modulus_n
        and key1.exponent_e == key2.exponent_e
        and key1.prime_p == key2.prime_p
        and key1.group_generator_g == key2.group_generator_g
        and key1.group_order_q == key2.group_order_q
        and key1.key_value_y == key2.key_value_y
        and key1.creation_time == key2.creation_time
        )


def merge_sigpairs(parts):
    # "Since a self-signature contains important information about the key's
    #  use, an implementation SHOULD allow the user to rewrite the self-
    #  signature, and important information in it, such as preferences and
    #  key expiration."
    #
    #  "[...]"
    #
    # "An implementation that encounters multiple self-signatures on the
    #  same object may resolve the ambiguity in any way it sees fit, but it
    #  is RECOMMENDED that priority be given to the most recent self-
    #  signature."

    m = OrderedDict()
    for part in parts:
        old_sigs = m.setdefault(part, [])
        for sig in part.signatures:
            sig_key = signature_key(sig)
            for sig2 in old_sigs:
                sig_key2 = signature_key(sig2)
                if sig_key != sig_key2:
                    old_sigs.append(sig)

    for part, sigs in m.items():
        part.signatures = []

        # If there are multiple self-signatures, just add the newest one at
        # the head of the list. All other signatures are appended in order.
        # All self-signatures should already be validated by this point.
        selfsig = None
        for sig in sigs:
            if sig.is_self_signature() and selfsig:
                if sig.creation_time > selfsig.creation_time:
                    selfsig = sig
            else:
                part.signatures.append(sig)
        part.signatures.insert(0, selfsig)


def merge_sigpair_lists(part1, part2):
    return merge_sigpairs(part1 + part2)


_marker = object()


def signature_key(sig):
    return (
        sig.version,
        sig.signature_type,
        sig.public_key_algorithm,
        sig.hash_algorithm,
        sig.creation_time,
        set(sig.issuer_key_ids),
        )


def merge(key, candidate_key):
    if not keys_equivalent(key, candidate_key):
        return key

    signatures = candidate_key.signatures
    old_sigs = OrderedDict()
    for sig in signatures:
        sig_key = signature_key(sig)
        for sig2 in old_sigs:
            sig_key2 = signature_key(sig2)
            if sig_key == sig_key2:
                break
        else:
            # Only called if we never break
            old_sigs[sig_key] = sig

    old_user_ids = candidate_key.user_ids
    old_user_attributes = candidate_key.user_attributes
    old_subkeys = candidate_key.subkeys

    for sig in old_sigs.values():
        # FIX
        if sig not in key.signatures:
            key.signatures.append(sig)

    key.user_ids = merge_sigpair_lists(
        key.user_ids,
        old_user_ids
        )
    key.user_attributes = merge_sigpair_lists(
        key.user_attributes,
        old_user_attributes
        )
    key.subkeys = merge_sigpair_lists(
        key.subkeys,
        old_subkeys
        )

    return key


def merge_key(key, db):
    key_id = key.key_id
    if hasattr(db, 'get_key_by_hash'):
        if db.get_key_by_hash(utils.hash_entire_key(key)):
            return key

    potential_merges = list(db.search(key_id=key_id))
    if potential_merges:
        key = merge(key, potential_merges[0])

    return key
