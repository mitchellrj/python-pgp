from pgp.commands.gpg.sign_ import SignCommand


class Command(SignCommand):

    def __init__(self, force_v3_sigs, force_v4_certs):
        SignCommand.__init__(self, force_v3_sigs, force_v4_certs)
