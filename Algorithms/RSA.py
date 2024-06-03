import rsa
from Algorithms.FileUtil import FileUtil


class RSA:
    @staticmethod
    def encrypt_message(message, key):
        return rsa.encrypt(message.encode('utf-8'), key)

    @staticmethod
    def decrypt_message(cyphertext, key):
        return rsa.decrypt(cyphertext, key).decode('utf-8')

    @staticmethod
    def generate_key(size):
        return rsa.newkeys(size)  # returns tuple, first is public key, second is private key

    @staticmethod
    def import_key():
        key_string = FileUtil.import_pem("KEYS")
        splitted = key_string.split('\t')
        public_key = rsa.PublicKey.load_pkcs1(splitted[0].encode('utf-8'))
        private_key = rsa.PrivateKey.load_pkcs1(splitted[1].encode('utf-8'))
        return (public_key, private_key)

    @staticmethod
    def export_key(keys):
        public_key = keys[0]
        private_key = keys[1]
        public_key_string = public_key.save_pkcs1().decode('utf-8')
        private_key_string = private_key.save_pkcs1().decode('utf-8')
        key_string = f"{public_key_string}\t{private_key_string}"
        FileUtil.export_pem(key_string, "KEYS")

    @staticmethod
    def import_public():
        key_string = FileUtil.import_pem("PUBLIC_KEY")
        return rsa.PublicKey.load_pkcs1(key_string.encode('utf-8'), format="PEM")

    @staticmethod
    def export_public(key):
        key_string = key.save_pkcs1(format="PEM").decode('utf-8')
        FileUtil.export_pem(key_string, "PUBLIC_KEY")
