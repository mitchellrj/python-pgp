from pgp.commands.gpg.check_sigs import Command as CheckSigsCommand
from pgp.commands.gpg.list_sigs import Command as ListSigsCommand


class EncryptSymmetricAndSign(object):

    multifile = True

    def __init__(self):
        pass

    def run(self, *args):
        pass


class EncryptAndSign(object):

    multifile = True

    def __init__(self):
        pass

    def run(self, *args):
        pass


class SymmetricAndSign(object):

    def __init__(self):
        pass

    def run(self, *args):
        pass


class FingerprintCheckSigs(CheckSigsCommand):

    def __init__(self, show_fingerprints, *args, **kwargs):
        CheckSigsCommand.__init__(self, show_fingerprints=1, *args, **kwargs)


class FingerprintListSigs(ListSigsCommand):

    def __init__(self, show_fingerprints, *args, **kwargs):
        CheckSigsCommand.__init__(self, show_fingerprints=show_fingerprints,
                                  *args, **kwargs)
