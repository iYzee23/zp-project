from PublicRingRow import PublicRingRow
from Algorithms.SHA1 import SHA1
from Algorithms.AES128 import AES128
from Algorithms.DES3 import DES3


class PrivateRingRow(PublicRingRow):
    def __init__(self, public_key, private_key, password, name, mail, algorithm):
        super().__init__(public_key, name, mail)
        self.algorithm = algorithm
        self.hashed_password = self.hash_password(password)
        self.encrypted_private_key = self.encrypt_private_key(private_key, self.hashed_password)

    def verify_password(self, password):
        hashed_password = self.hash_password(password)
        return hashed_password == self.hashed_password

    def get_private_key(self, password):
        hashed_password = self.hash_password(password)
        if hashed_password == self.hashed_password:
            pass
        return None

    def hash_password(self, password):
        return SHA1.generate_hash(password)

    def encrypt_private_key(self, private_key, hashed_password):
        if self.algorithm == "AES128":
            return AES128.encrypt_message(private_key, hashed_password)
        else:
            return DES3.encrypt_message(private_key, hashed_password)

    def decrypt_private_key(self, enc_private_key, hashed_password):
        if self.algorithm == "AES128":
            return AES128.decrypt_message(enc_private_key, hashed_password)
        else:
            return DES3.decrypt_message(enc_private_key, hashed_password)

    def __str__(self):
        str_upper = super().__str__()
        str_algorithm = f"Algorithm: {self.algorithm}\n"
        return str_upper + str_algorithm
