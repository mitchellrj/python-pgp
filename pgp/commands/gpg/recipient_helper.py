from argparse import ArgumentError
from pgp.commands.gpg.exceptions import FatalException


class RecipientHelper(object):

    def __init__(self, trustdb_helper, keyring_helper, recipients,
                 hidden_recipients, encrypt_to, hidden_encrypt_to,
                 no_encrypt_to, groups, ungroups, no_groups):
        self.trustdb_helper = trustdb_helper
        self.keyring_helper = keyring_helper

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

    def find_recipient_public_key(self, recipient_string):
        # https://tools.ietf.org/html/rfc4880#section-5.2.3.21
        # The standard is ambiguous here about which flag we should obey when
        # choosing a subkey. Do we want 0x04 (communications) or 0x08
        # (storage)?
        #
        # Since these are called "messages", we will assume 0x04.
        public_key = self.keyring_helper.find_recipient(recipient_string)
        if not public_key:
            raise FatalException(
                u'Could not find a public key for {0}.'.format(
                    repr(recipient_string)
                ))
        if public_key.revoked:
            raise FatalException(
                u'Public key for {0} is revoked'.format(
                    repr(recipient_string)))
        for subkey in public_key.subkeys:
            # TODO: expert
            if subkey.revoked:
                continue
            if subkey.may_encrypt_comms:
                return subkey
        if public_key.may_encrypt_comms:
            return public_key

    def get_recipient_public_key(self, recipient_string):
        key = self.find_recipient_public_key(recipient_string)
        if not self.verify_trust(key):
            # TODO: prompt
            pass
        return key

    def get_recipient_public_keys(self):
        result = []
        for r in self.get_recipients():
            result.append(self.get_recipient_public_key(r))
        return result

    def get_hidden_recipient_public_keys(self):
        result = []
        for r in self.get_hidden_recipients():
            result.append(self.get_recipient_public_key(r))
        return result

    def verify_trust(self, key):
        return self.trustdb_helper.check(key)
