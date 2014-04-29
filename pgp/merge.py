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


IGNORED_KEYS = ('data', 'data_file_hash', 'data_file', 'signatures',
                'key_hash', '_skeleton', '_obj', '_packet', '_sig_hash2',
                '_data')


def key_data_equal(key_data, key):
    old_key_data = {}
    old_key_data.update(key.properties)
    if old_key_data.get('_skeleton', False):
        # This key was added as an endpoint for a signature with
        # incomplete information. Let the merge tear it down and update it.
        return True

    for k in set(list(old_key_data.keys()) + list(key_data.keys())):
        if k in IGNORED_KEYS:
            continue
        if old_key_data.get(k, None) != key_data.get(k, None):
            return False

    return True


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

    part_map = {}
    m = OrderedDict()
    for part in parts:
        part_key_items = {}
        part_key_items.update(part)
        part_key_items.pop('signatures', None)
        part_key_items.pop('_data', None)
        part_key = repr(sorted([(k, v)
                                for k, v in part_key_items.items()
                                if k not in IGNORED_KEYS]))
        part_map[part_key] = part
        old_sigs = m.setdefault(part_key, [])
        for sig in part.get('signatures', []):
            for sig2 in old_sigs:
                if not compare_data(sig, sig2):
                    old_sigs.append(sig)

    result = []
    for part_key, sigs in m.items():
        part = part_map[part_key]
        part['signatures'] = []

        # If there are multiple self-signatures, just add the newest one at
        # the head of the list. All other signatures are appended in order.
        # All self-signatures should already be validated by this point.
        selfsig = None
        for sig in sigs:
            if sig['selfsig'] and selfsig:
                if sig['creation_time'] > selfsig['creation_time']:
                    selfsig = sig
            else:
                part['signatures'].append(sig)
        part['signatures'].insert(0, selfsig)
        result.append(part)
    return result


def merge_sigpair_lists(part1, part2):
    return merge_sigpairs(part1 + part2)


_marker = object()


def compare_data(d1, d2):
    for k in set(list(d1.keys()) + list(d2.keys())):
        if k in IGNORED_KEYS:
            continue
        if d1.get(k, _marker) != d2.get(k, _marker):
            return False
    return True


def merge(key_data, candidate_node):
    if not key_data_equal(key_data, candidate_node):
        return None, key_data

    signature_nodes = utils.get_signatures(candidate_node)
    old_sigs = []
    for node in signature_nodes:
        sig = {}
        sig.update(node.properties)
        for sig2 in old_sigs:
            if compare_data(sig, sig2):
                break
        else:
            # Only called if we never break
            old_sigs.append(sig)

    old_user_ids = utils.get_user_ids(candidate_node)
    old_user_attributes = utils.get_user_attributes(candidate_node)
    old_subkeys = utils.get_subkeys(candidate_node)

    for sig in old_sigs:
        if sig not in key_data['signatures']:
            key_data['signatures'].append(sig)

    key_data['user_ids'] = merge_sigpair_lists(
                                key_data.get('user_ids', []),
                                list(map(node_to_dict, old_user_ids))
                            )
    key_data['user_attributes'] = merge_sigpair_lists(
                                key_data.get('user_attributes', []),
                                list(map(node_to_dict, old_user_attributes))
                            )
    key_data['subkeys'] = merge_sigpair_lists(
                                key_data.get('subkeys', []),
                                list(map(node_to_dict, old_subkeys))
                            )

    return candidate_node, key_data


def key_to_merge_updates(key_data, db):
    key_id = key_data['key_id']
    if db.get_public_key_by_hash(key_data['key_hash']):
        return None

    potential_merge = db.get_public_key_by_id(key_id[-8:])
    if potential_merge:
        target, key_data = merge(key_data, potential_merge)
        if target:
            key_data['_obj'] = target

    return key_data
