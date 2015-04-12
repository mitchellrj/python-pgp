class ValidationAndVerificationHelper(object):

    def __init__(self, trustdb_helper, faked_system_time,
                 allow_non_selfsigned_uid, allow_freeform_uid,
                 ignore_time_conflict, ignore_valid_from,
                 ignore_crc_error, ignore_mdc_error,
                 skip_sig_verification):
        self.trustdb_helper = trustdb_helper
        self.faked_system_time = faked_system_time
        self.allow_non_selfsigned_uid = allow_non_selfsigned_uid
        self.allow_freeform_uid = allow_freeform_uid
        self.ignore_time_conflict = ignore_time_conflict
        self.ignore_valid_from = ignore_valid_from
        self.ignore_crc_error = ignore_crc_error
        self.ignore_mdc_error = ignore_mdc_error
        self.skip_sig_verification = skip_sig_verification