from .list_ import ListCommand


class Command(ListCommand):

    def __init__(self, list_options, default_prefs_list):
        ListCommand.__init__(self, list_options)
        self.default_prefs_list = default_prefs_list
