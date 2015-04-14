from .list_ import ListCommand


class Command(ListCommand):

    def __init__(self, list_options, show_fingerprints=0):
        ListCommand.__init__(self, list_options)
