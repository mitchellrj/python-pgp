from pgp.commands.gpg.sign_ import SignCommand


class Command(SignCommand):

    def __init__(self, formatter, io_helper, force_v3_sigs,
                 force_v4_certs, signature_notations, certification_notations,
                 notations, sig_policy_url, cert_policy_url, policy_url,
                 preferred_keyserver, default_keyserver_url,
                 message_filename):

        SignCommand.__init__(
            self, io_helper, force_v3_sigs, force_v4_certs,
            signature_notations, certification_notations, notations,
            sig_policy_url, cert_policy_url, policy_url,
            preferred_keyserver, default_keyserver_url, message_filename)
