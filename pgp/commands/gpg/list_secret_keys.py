from .list_ import ListCommand


class Command(ListCommand):

    def __init__(self, list_options):
        ListCommand.__init__(self, list_options)
