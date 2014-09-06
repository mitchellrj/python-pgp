import pkg_resources

from pgp import armor
from pgp.db.gpg import GPGDatabase
from pgp.packets import constants
from pgp.packets import parse_binary_packet_data
from pgp.packets import parse_ascii_packet_data
from pgp.transferrable_keys import TransferablePublicKey
from pgp.transferrable_keys import TransferableSecretKey


VERSION = pkg_resources.get_distribution('pgp').version


def read_key(data, armored=False):
    if armor.is_armor(data):
        # Assume the user made a mistake
        if isinstance(data, bytes):
            data = data.decode('us-ascii')
        armored = True
    if armored:
        fn = parse_ascii_packet_data
    else:
        fn = parse_binary_packet_data

    packets = list(fn(data))

    if packets[0].type == constants.PUBLIC_KEY_PACKET_TYPE:
        return TransferablePublicKey.from_packets(packets)
    elif packets[0].type == constants.SECRET_KEY_PACKET_TYPE:
        return TransferableSecretKey.from_packets(packets)
    else:
        raise ValueError('Unexpected packet')


def read_key_file(filename, armored=False):
    if armored:
        mode = 'r'
    else:
        mode = 'rb'

    with open(filename, mode) as fh:
        return read_key(fh.read(), armored)


def serialize_key(key, armored=False, header_format=None):
    if header_format is None:
        header_format = constants.OLD_PACKET_HEADER_TYPE
    data = b''.join(map(bytes, key.to_packets(header_format)))
    if armored:
        if isinstance(key, TransferablePublicKey):
            data_type = armor.PGP_PUBLIC_KEY_BLOCK
        elif isinstance(key, TransferableSecretKey):
            data_type = armor.PGP_PRIVATE_KEY_BLOCK

        data = str(armor.ASCIIArmor(
                data_type, data,
                version='Python PGP {0}'.format(VERSION)))

    return data


def write_key_file(key, filename, armored=False):
    data = serialize_key(key, armored)
    mode = 'wb'
    if armored:
        mode = 'w'

    with open(filename, mode) as fh:
        fh.write(data)


def verify():
    pass


def generate(public_key_algorithm, bits, hash_algorithm, user_id, password):
    pass


def get_gnupg_db():
    db = GPGDatabase()
    db.load_default_resources()
    return db
