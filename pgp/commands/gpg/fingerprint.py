from pgp.commands.gpg.list_keys import Command as ListKeysCommand


class Command(ListKeysCommand):

    def __init__(self, *args, **kwargs):
        ListKeysCommand.__init__(self, show_fingerprints=True, *args,
                                 **kwargs)
