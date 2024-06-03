import datetime
from MessageComponent import MessageComponent


class SignatureComponent(MessageComponent):
    def __init__(self, key_id, digest, private_key):
        super().__init__(key_id)
        self.digest = SignatureComponent.encrypt_digest(digest, private_key)

    def __str__(self):
        str_upper = super().__str__()
        str_digest = f"Digest: {self.digest}\n"
        str_delimiter = f"#####\n"
        return str_upper + str_digest + str_delimiter

    @staticmethod
    def encrypt_digest(digest, private_key):
        pass

    @staticmethod
    def decrypt_digest(enc_digest, public_key):
        pass

    @staticmethod
    def create_signature_component_object(signature_string):
        lines = signature_string.split('\n')
        key_id = lines[1].split('KeyID: ')[1]
        digest = lines[2].split('Digest: ')[1]
        return {
            "key_id": key_id,
            "enc_digest": digest
        }
