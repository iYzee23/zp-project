import datetime


class MessageComponent:
    def __init__(self, key_id):
        self.timestamp = datetime.datetime.now()
        self.key_id = key_id

    def __str__(self):
        str_timestamp = f"Timestamp: {self.timestamp}\n"
        str_key_id = f"KeyID: {self.key_id}\n"
        return str_timestamp + str_key_id
