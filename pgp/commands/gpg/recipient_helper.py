from argparse import ArgumentError


class RecipientHelper(object):

    def __init__(self, trustdb_helper, recipients, hidden_recipients, encrypt_to,
                 hidden_encrypt_to, no_encrypt_to, groups, ungroups,
                 no_groups):
        self.trustdb_helper = trustdb_helper

        if no_groups:
            groups = []
        self.groups = {}
        for val in groups:
            if '=' not in val:
                raise ArgumentError(
                    u'--group',
                    u'Group values must contain `=`')
            name, combined_recipients = val.split('=')
            recipients = combined_recipients.split()
            self.groups.setdefault(name, []).extend(recipients)

        for name in ungroups:
            if name not in self.groups:
                continue
            del self.groups[name]

        self.recipients = recipients
        self.hidden_recipients = hidden_recipients
        if no_encrypt_to:
            encrypt_to = []
            hidden_encrypt_to = []
        self.encrypt_to = encrypt_to
        self.hidden_encrypt_to = hidden_encrypt_to

    def get_recipients(self):
        result = []
        for r in self.recipients:
            if r in self.groups:
                result.expand(self.groups[r])
            else:
                result.append(r)
        for r in result:
            self.verify_trust(r)
        for r in self.encrypt_to:
            if r in self.groups:
                result.expand(self.groups[r])
            else:
                result.append(r)
        return result

    def get_hidden_recipients(self):
        result = []
        for r in self.hidden_recipients:
            if r in self.groups:
                result.expand(self.groups[r])
            else:
                result.append(r)
        for r in result:
            self.verify_trust(r)
        for r in self.hidden_encrypt_to:
            if r in self.groups:
                result.expand(self.groups[r])
            else:
                result.append(r)
        return result

    def verify_trust(self, recipient):
        pass
