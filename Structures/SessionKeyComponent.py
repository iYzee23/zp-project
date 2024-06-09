import base64
from Structures.MessageComponent import MessageComponent
from Algorithms.RSA import RSA


class SessionKeyComponent(MessageComponent):
    def __init__(self, key_id, session_key, public_key):
        super().__init__(key_id)
        self.session_key = SessionKeyComponent.encrypt_session_key(session_key, public_key)

    def __str__(self):
        str_upper = super().__str__()
        str_session_key = f"SessionKey: {self.session_key}\n"
        str_delimiter = f"#####\n"
        return str_upper + str_session_key + str_delimiter

    @staticmethod
    def encrypt_session_key(session_key, public_key):
        session_key = base64.b64encode(session_key).decode("utf-8")
        return RSA.encrypt_message(session_key, public_key)

    @staticmethod
    def decrypt_session_key(enc_session_key, private_key):
        result = RSA.decrypt_message(enc_session_key, private_key)
        return base64.b64decode(result.encode("utf-8"))

    @staticmethod
    def create_session_key_component_object(session_string):
        lines = session_string.split('\n')
        if len(lines) != 4:
            raise ValueError("Invalid session")
        key_id = lines[1].split('KeyID: ')[1]
        session_key = lines[2].split('SessionKey: ')[1]
        return {
            "key_id": key_id,
            "enc_session_key": session_key
        }
