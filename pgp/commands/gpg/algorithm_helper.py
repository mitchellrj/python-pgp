from pgp.commands.gpg.arguments import Compliance


class AlgorithmHelper(object):

    def __init__(self, enable_dsa2, z_compress_level, bz_compress_level,
                 compress_level, personal_cipher_preferences,
                 personal_digest_preferences, personal_compress_preferences,
                 s2k_cipher_algo, s2k_digest_algo, s2k_mode, s2k_count,
                 compliance, cipher_algo, digest_algo, compress_algo,
                 cert_digest_algo, disabled_cert_cipher_algos,
                 disabled_pubkey_algos,
                 ):
        # True, False or None
        self.enable_dsa2 = enable_dsa2
        if compress_level is not None:
            z_compress_level = compress_level
            bz_compress_level = compress_level
        self.z_compress_level = z_compress_level
        self.bz_compress_level = bz_compress_level
        self.personal_cipher_preferences = personal_cipher_preferences
        self.personal_digest_preferences = personal_digest_preferences
        self.personal_compress_preferences = personal_compress_preferences
        self.s2k_cipher_algo = s2k_cipher_algo
        self.s2k_digest_algo = s2k_digest_algo
        self.s2k_mode = s2k_mode
        self.s2k_count = s2k_count
        self.compliance = compliance
