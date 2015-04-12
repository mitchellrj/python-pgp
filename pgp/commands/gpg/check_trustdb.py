class Command(object):

    def __init__(self, trustdb_helper):
        self.trustdb_helper = trustdb_helper

    def run(self):
        self.trustdb_helper.check_trustdb()
