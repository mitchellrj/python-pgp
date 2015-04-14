from pgp.commands.gpg.exceptions import FatalException
from pgp.commands.gpg.message_ import MessageCommand


class Command(MessageCommand):

    multifile = True

    def __init__(self, io_helper, recipient_helper,
                 algorithm_helper,
                 message_filename, for_your_eyes_only,
                 throw_keys, escape_from_lines, set_filesize):
        MessageCommand.__init__(self, io_helper, message_filename,
                                set_filesize, for_your_eyes_only)
        self.recipient_helper = recipient_helper
        self.algorithm_helper = algorithm_helper
        self.throw_keys = throw_keys

    def file_to_literal_message(self, filename, binary=True):
        msg = MessageCommand.file_to_literal_message(
            self, filename, binary=binary)
        msg = msg.compress(self.algorithm_helper.get_compression_algorithm(),
                           self.algorithm_helper.get_compression_level())
        return msg

    def pubkey_encrypt_message(self, msg):
        session_key = None
        use_mdc = True
        # Choose an algorithm supported by all our recipients
        preferred_ciphers = \
            self.algorithm_helper.get_preferred_ciphers_for_encryption()
        recipient_public_keys = \
            self.recipient_helper.get_recipient_public_keys()
        hidden_recipient_public_keys = \
            self.recipient_helper.get_hidden_recipient_public_keys()
        if self.throw_keys:
            # All recipients are hidden
            hidden_recipient_public_keys += recipient_public_keys
            recipient_public_keys = []

        all_keys = recipient_public_keys + hidden_recipient_public_keys
        for cipher in preferred_ciphers:
            acceptable = True
            for key in all_keys:
                if cipher not in key.preferred_symmetric_algorithms:
                    acceptable = False
                    break
            if acceptable:
                break
        if not acceptable:
            raise FatalException(
                u'Cannot find symmetric cipher acceptable by all recipients.'
                )

        if self.algorithm_helper.get_mdc_forced():
            use_mdc = True
        elif self.algorithm_helper.get_mdc_disabled():
            use_mdc = False
        else:
            # check recipients for compatibility
            for key in all_keys:
                if not key.supports_modification_detection:
                    use_mdc = False
                    break
        return msg.public_key_encrypt(
            cipher, public_keys=recipient_public_keys,
            hidden_public_keys=hidden_recipient_public_keys,
            session_key=session_key, integrity_protect=use_mdc
            )

    def process_message(self, msg):
        return self.pubkey_encrypt_message(msg)
