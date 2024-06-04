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
    def import_keys_tk():
        key_string = FileUtil.import_pem("KEYS")
        splitted = key_string.split('\t')
        public_key = rsa.PublicKey.load_pkcs1(splitted[0].encode("utf-8"))
        private_key = rsa.PrivateKey.load_pkcs1(splitted[1].encode("utf-8"))
        return (public_key, private_key)

    @staticmethod
    def import_keys(cnt):
        with open(f"Keys/InitKeys/init_public_private_{cnt}.pem", 'r') as file:
            pem_content = file.read()
            start = f"-----BEGIN KEYS-----\n"
            end = f"-----END KEYS-----\n"
            pem_content = pem_content.replace(start, "").replace(end, "").strip()
            base64_data = pem_content.encode("utf-8")
            byte_data = base64.b64decode(base64_data)
            key_string = byte_data.decode("utf-8")

        splitted = key_string.split('\t')
        public_key = rsa.PublicKey.load_pkcs1(splitted[0].encode("utf-8"))
        private_key = rsa.PrivateKey.load_pkcs1(splitted[1].encode("utf-8"))
        return (public_key, private_key)

    @staticmethod
    def export_keys_tk(public_key, private_key):
        public_key_string = public_key.save_pkcs1().decode("utf-8")
        private_key_string = private_key.save_pkcs1().decode("utf-8")
        key_string = f"{public_key_string}\t{private_key_string}"
        FileUtil.export_pem(key_string, "KEYS")

    @staticmethod
    def export_keys(public_key, private_key, cnt):
        public_key_string = public_key.save_pkcs1().decode("utf-8")
        private_key_string = private_key.save_pkcs1().decode("utf-8")
        key_string = f"{public_key_string}\t{private_key_string}"

        with open(f"Keys/public_private_{cnt}.pem", 'w') as file:
            byte_data = key_string.encode("utf-8")
            base64_data = base64.b64encode(byte_data)
            content = base64_data.decode("utf-8")
            start = f"-----BEGIN KEYS-----\n"
            end = f"-----END KEYS-----\n"
            pem_content = f"{start}{content}\n{end}"
            file.write(pem_content)

    @staticmethod
    def import_public_tk():
        key_string = FileUtil.import_pem("PUBLIC_KEY")
        return rsa.PublicKey.load_pkcs1(key_string.encode("utf-8"), format="PEM")

    @staticmethod
    def export_public_tk(public_key):
        key_string = public_key.save_pkcs1(format="PEM").decode("utf-8")
        FileUtil.export_pem(key_string, "PUBLIC_KEY")

    @staticmethod
    def export_public(public_key, cnt):
        key_string = public_key.save_pkcs1(format="PEM").decode("utf-8")

        with open(f"Keys/public_{cnt}.pem", 'w') as file:
            byte_data = key_string.encode("utf-8")
            base64_data = base64.b64encode(byte_data)
            content = base64_data.decode("utf-8")
            start = f"-----BEGIN PUBLIC_KEY-----\n"
            end = f"-----END PUBLIC_KEY-----\n"
            pem_content = f"{start}{content}\n{end}"
            file.write(pem_content)
