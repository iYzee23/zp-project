import rsa
import base64
from Algorithms.FileUtil import FileUtil


class RSA:
    @staticmethod
    def encrypt_message(message, public_key):
        result = rsa.encrypt(message.encode("utf-8"), public_key)
        return base64.b64encode(result).decode("utf-8")

    @staticmethod
    def decrypt_message(cyphertext, private_key):
        cyphertext = base64.b64decode(cyphertext.encode("utf-8"))
        return rsa.decrypt(cyphertext, private_key).decode("utf-8")

    @staticmethod
    def sign_message(message, private_key):
        message_bytes = message.encode('utf-8')
        signature = rsa.sign(message_bytes, private_key, 'SHA-1')
        return base64.b64encode(signature).decode('utf-8')

    @staticmethod
    def verify_signature(message, signature, public_key):
        message_bytes = message.encode('utf-8')
        signature_bytes = base64.b64decode(signature.encode('utf-8'))
        try:
            rsa.verify(message_bytes, signature_bytes, public_key)
            return True
        except rsa.VerificationError:
            return False

    @staticmethod
    def generate_keys(size):
        return rsa.newkeys(size)  # Returns tuple, first is public key, second is private key

    @staticmethod
    def import_key():
        key_string = FileUtil.import_pem("KEYS")
        splitted = key_string.split('\t')
        public_key = rsa.PublicKey.load_pkcs1(splitted[0].encode("utf-8"))
        private_key = rsa.PrivateKey.load_pkcs1(splitted[1].encode("utf-8"))
        return (public_key, private_key)

    @staticmethod
    def export_key(keys):
        public_key = keys[0]
        private_key = keys[1]
        public_key_string = public_key.save_pkcs1().decode("utf-8")
        private_key_string = private_key.save_pkcs1().decode("utf-8")
        key_string = f"{public_key_string}\t{private_key_string}"
        FileUtil.export_pem(key_string, "KEYS")

    @staticmethod
    def import_public():
        key_string = FileUtil.import_pem("PUBLIC_KEY")
        return rsa.PublicKey.load_pkcs1(key_string.encode("utf-8"), format="PEM")

    @staticmethod
    def export_public(key):
        key_string = key.save_pkcs1(format="PEM").decode("utf-8")
        FileUtil.export_pem(key_string, "PUBLIC_KEY")
