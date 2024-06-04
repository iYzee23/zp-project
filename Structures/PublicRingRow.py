import datetime


class PublicRingRow:
    def __init__(self, public_key, name, mail):
        self.timestamp = datetime.datetime.now()
        self.public_key = public_key
        self.key_id = public_key.n % (2**64)
        self.user_id = name + "###" + mail

    def __str__(self):
        str_timestamp = f"Timestamp: {self.timestamp}\n"
        str_public_key = f"PublicKey: {self.public_key}\n"
        str_key_id = f"KeyID: {self.key_id}\n"
        str_user_id = f"UserID: {self.user_id}\n"
        return str_timestamp + str_public_key + str_key_id + str_user_id
