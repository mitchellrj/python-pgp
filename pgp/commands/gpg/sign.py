from pgp.commands.gpg.sign_ import SignCommand
from pgp.packets.constants import SIGNATURE_OF_A_BINARY_DOCUMENT


class Command(SignCommand):

    def __init__(self, formatter, io_helper, keyring_helper,
                 algorithm_helper, faked_system_time, force_v3_sigs,
                 force_v4_certs, signature_notations, certification_notations,
                 notations, sig_policy_url, cert_policy_url, policy_url,
                 preferred_keyserver, default_keyserver_url,
                 message_filename, set_filesize, escape_from_lines,
                 for_your_eyes_only):

        SignCommand.__init__(
            self, io_helper, force_v3_sigs, force_v4_certs,
            signature_notations, certification_notations, notations,
            sig_policy_url, cert_policy_url, policy_url,
            preferred_keyserver, default_keyserver_url, message_filename,
            set_filesize, escape_from_lines, for_your_eyes_only)
        self.formatter = formatter
        self.io_helper = io_helper
        self.keyring_helper = keyring_helper
        self.algorithm_helper = algorithm_helper
        self.faked_system_time = faked_system_time

    def sign_message(self, msg, signature_type=None, one_pass=True):
        if signature_type is None:
            signature_type = SIGNATURE_OF_A_BINARY_DOCUMENT
        secret_key = self.keyring_helper.get_secret_key()
        signature_version = 4
        if self.force_v3_sigs:
            signature_version = 3
        msg.sign(secret_key, signature_version, signature_type,
                 self.algorithm_helper.get_signature_digest_algorithm(),
                 one_pass=one_pass)

    def process_message(self, msg):
        return self.sign_message(msg)

    def postprocess_message(self, msg):
        compress_algo = self.algorithm_helper.get_compression_algorithm()
        compress_level = self.algorithm_helper.get_compression_level()
        if compress_algo:
            msg = msg.compress(compress_algo, compress_level)
        return msg

    def run(self, filename=None):
        msg = self.file_to_literal_message(filename)
        signed_message = self.sign_message(msg)
        message = self.postprocess_message(signed_message)
        self.output(message, filename)

    def output(self, message, filename):
        output_filename = self.formatter.make_output_filename(filename)
        self.io_helper.write_output(
            self.formatter.format_message(message),
            output_filename=output_filename
            )
