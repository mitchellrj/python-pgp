class MultifileCommand(object):

    def __init__(self, subcommand):
        self.subcommand = subcommand

    def run(self, *args):
        for arg in self.args:
            self.subcommand.run(arg)
