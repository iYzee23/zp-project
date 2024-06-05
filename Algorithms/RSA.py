import binascii
import datetime

import rsa
import base64
from Algorithms.FileUtil import FileUtil
from Structures.PublicRingRow import PublicRingRow
from Structures.PrivateRingRow import PrivateRingRow


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

    @staticmethod
    def import_private_ring_row_tk(password):
        try:
            private_ring_row_string = FileUtil.import_pem("KEYS")

            if private_ring_row_string is not None:
                split_string = private_ring_row_string.split("\t")


                timestamp = datetime.datetime.strptime(split_string[0], "%Y-%m-%d %H:%M:%S.%f")
                public_key = rsa.PublicKey.load_pkcs1(split_string[1].encode("utf-8"), format="PEM")
                algorithm = split_string[3]
                private_key = rsa.PrivateKey.load_pkcs1(split_string[4].encode("utf-8"))
                private_ring_row = PrivateRingRow(public_key, private_key, password, "", "", algorithm)
                private_ring_row.timestamp = timestamp
                private_ring_row.user_id = split_string[2]

                return private_ring_row

            return None

        except binascii.Error as e:
            raise ValueError("This .pem file is not in a correct format") from e

    @staticmethod
    def import_public_ring_row_tk():
        try:
            public_ring_row_string = FileUtil.import_pem("PUBLIC_KEY")

            if public_ring_row_string is not None:
                split_string = public_ring_row_string.split("\t")
                timestamp = datetime.datetime.strptime(split_string[0], "%Y-%m-%d %H:%M:%S.%f")
                public_key = rsa.PublicKey.load_pkcs1(split_string[1].encode("utf-8"), format="PEM")
                public_ring_row = PublicRingRow(public_key, "", "")
                public_ring_row.timestamp = timestamp
                public_ring_row.user_id = split_string[2]

                return public_ring_row

            return None

        except binascii.Error as e:
            raise ValueError("This .pem file is not in a correct format") from e

    @staticmethod
    def export_public_ring_row_tk(public_ring_row):
        str_timestamp = str(public_ring_row.timestamp)
        str_public_key = public_ring_row.public_key.save_pkcs1(format="PEM").decode("utf-8")
        str_user_id = str(public_ring_row.user_id)
        public_ring_row_string = f"{str_timestamp}\t{str_public_key}\t{str_user_id}"

        FileUtil.export_pem(public_ring_row_string, "PUBLIC_KEY")

    @staticmethod
    def export_private_ring_row_tk(private_ring_row, password):
        str_timestamp = str(private_ring_row.timestamp)
        str_public_key = private_ring_row.public_key.save_pkcs1(format="PEM").decode("utf-8")
        str_user_id = str(private_ring_row.user_id)
        str_algorithm = str(private_ring_row.algorithm)
        private_key = private_ring_row.get_private_key(password)
        str_private_key = private_key.save_pkcs1(format="PEM").decode("utf-8")
        private_ring_row_string = f"{str_timestamp}\t{str_public_key}\t{str_user_id}\t{str_algorithm}\t{str_private_key}"

        FileUtil.export_pem(private_ring_row_string, "KEYS")
