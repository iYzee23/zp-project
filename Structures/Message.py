import zlib
import secrets
import base64
from PrivateRingRow import PrivateRingRow
from PublicRingRow import PublicRingRow
from SignatureComponent import SignatureComponent
from SessionKeyComponent import SessionKeyComponent
from Options import Options
from Algorithms.SHA1 import SHA1
from Algorithms.AES128 import AES128
from Algorithms.DES3 import DES3


class Message:
    def __init__(self, data, filename, timestamp, options: Options):
        self.options = options
        self.filename = filename
        self.timestamp = timestamp
        self.data = data

    def __str__(self):
        str_filename = f"Filename: {self.filename}\n"
        str_timestamp = f"Timestamp: {self.timestamp}\n"
        str_data = f"Data: {self.data}\n"
        return str_filename + str_timestamp + str_data

    @staticmethod
    def create_message_object(message_string, options):
        lines = message_string.split('\n')
        filename = lines[0].split('Filename: ')[1]
        timestamp = lines[1].split('Timestamp: ')[1]
        data = lines[2].split('Data: ')[1]
        return Message(data, filename, timestamp, options)

    @staticmethod
    def generate_signature(data):
        return SHA1.generate_hash(data)

    @staticmethod
    def generate_signature_component(message, sender_private_ring: PrivateRingRow, password):
        key_id = sender_private_ring.key_id
        signature = Message.generate_signature(message.data)
        private_key = sender_private_ring.get_private_key(password)
        return SignatureComponent(key_id, signature, private_key)

    @staticmethod
    def generate_session_key(algorithm):
        if algorithm == "AES128":
            return secrets.token_bytes(16)
        else:
            return secrets.token_bytes(24)

    @staticmethod
    def generate_session_key_component(session_key, recipient_public_ring: PublicRingRow):
        key_id = recipient_public_ring.key_id
        public_key = recipient_public_ring.public_key
        return SessionKeyComponent(key_id, session_key, public_key)

    @staticmethod
    def encrypt_message(algorithm, session_key, data):
        if algorithm == "AES128":
            return AES128.encrypt_message(data, session_key)
        else:
            return DES3.encrypt_message(data, session_key)

    @staticmethod
    def send_message(message, sender_private_ring: PrivateRingRow, password, recipient_public_ring: PublicRingRow):
        msg = message.__str__()

        if message.options.authentication:
            signature_component = Message.generate_signature_component(message, password, sender_private_ring)
            msg = signature_component.__str__() + msg

        if message.options.compression:
            byte_data = msg.encode("utf-8")
            msg = zlib.compress(byte_data)

        if message.options.encryption:
            session_key = Message.generate_session_key(message.options.algorithm)
            msg = Message.encrypt_message(message.options.algorithm, session_key, msg)
            session_key_component = Message.generate_session_key_component(session_key, recipient_public_ring)
            msg = session_key_component.__str__() + msg

        if message.options.radix64:
            byte_data = msg.encode("utf-8")
            base64_data = base64.b64encode(byte_data)
            msg = base64_data.decode("utf-8")

        return message.options.__str__() + msg

    @staticmethod
    def decrypt_message(algorithm, session_key, data):
        if algorithm == "AES128":
            return AES128.decrypt_message(data, session_key)
        else:
            return DES3.decrypt_message(data, session_key)

    @staticmethod
    def verify_signature(digest, data):
        new_digest = Message.generate_signature(data)
        return digest == new_digest

    @staticmethod
    def receive_message(msg: str, recepient_private_ring: PrivateRingRow, password, sender_public_ring: PublicRingRow):
        options_str, msg = msg.split("#####\n")
        options = Options.create_options_object(options_str)

        if options.radix64 == "True":
            base64_data = msg.encode("utf8")
            byte_data = base64.b64decode(base64_data)
            msg = byte_data.decode("utf8")

        if options.encryption == "True":
            session_key_component_str, msg = msg.split("#####\n")
            session_key_component = SessionKeyComponent.create_session_key_component_object(session_key_component_str)
            enc_session_key = session_key_component["enc_session_key"]
            private_key = recepient_private_ring.get_private_key(password)
            session_key = SessionKeyComponent.decrypt_session_key(enc_session_key, private_key)
            msg = Message.decrypt_message(options.algoritm, session_key, msg)

        if options.compression == "True":
            byte_data = zlib.decompress(msg)
            msg = byte_data.decode("utf-8")

        message = Message.create_message_object(msg, options)

        if options.authentication == "True":
            signature_component_str, msg = msg.split("#####\n")
            signature_component = SignatureComponent.create_signature_component_object(signature_component_str)
            enc_digest = signature_component["enc_digest"]
            public_key = sender_public_ring.public_key
            digest = SignatureComponent.decrypt_digest(enc_digest, public_key)
            if Message.verify_signature(digest, message.data):
                print("Successful verification!")
                return message
            else:
                print("Unsuccessful verification!")
                return None

        return message
