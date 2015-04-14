from pgp.commands.gpg.message_ import MessageCommand


class SignCommand(MessageCommand):

    def __init__(self, io_helper, force_v3_sigs, force_v4_certs,
                 signature_notations, certification_notations, notations,
                 sig_policy_url, cert_policy_url, policy_url,
                 preferred_keyserver, default_keyserver_url,
                 message_filename, set_filesize, escape_from_lines,
                 for_your_eyes_only):
        MessageCommand.__init__(self, io_helper, message_filename,
                                set_filesize, escape_from_lines,
                                for_your_eyes_only)
        self.force_v3_sigs = force_v3_sigs
        self.force_v4_certs = force_v4_certs
        self.signature_notations = signature_notations
        self.certification_notations = certification_notations
        self.notations = notations
        self.sig_policy_url = sig_policy_url
        self.cert_policy_url = cert_policy_url
        self.policy_url = policy_url
        self.preferred_keyserver = preferred_keyserver
