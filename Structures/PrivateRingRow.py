import rsa
from Structures.PublicRingRow import PublicRingRow
from Algorithms.SHA1 import SHA1
from Algorithms.AES128 import AES128
from Algorithms.DES3 import DES3


class PrivateRingRow(PublicRingRow):
    def __init__(self, public_key, private_key, password, name, mail, algorithm):
        super().__init__(public_key, name, mail)
        self.algorithm = algorithm
        self.hashed_password = self.hash_password(password)
        self.encrypted_private_key = self.encrypt_private_key(private_key, self.hashed_password[:16])

    def verify_password(self, password):
        hashed_password = self.hash_password(password)
        return hashed_password == self.hashed_password

    def get_private_key(self, password):
        hashed_password = self.hash_password(password)
        if hashed_password == self.hashed_password:
            return self.decrypt_private_key(self.encrypted_private_key, self.hashed_password[:16])
        return None

    def hash_password(self, password):
        return SHA1.generate_hash(password).encode("utf-8")

    def encrypt_private_key(self, private_key, hashed_password):
        private_pem = private_key.save_pkcs1().decode("utf-8")
        if self.algorithm == "AES128":
            return AES128.encrypt_message(private_pem, hashed_password)
        else:
            return DES3.encrypt_message(private_pem, hashed_password)

    def decrypt_private_key(self, enc_private_key, hashed_password):
        if self.algorithm == "AES128":
            private_pem = AES128.decrypt_message(enc_private_key, hashed_password)
        else:
            private_pem = DES3.decrypt_message(enc_private_key, hashed_password)
        return rsa.PrivateKey.load_pkcs1(private_pem.encode("utf-8"))

    def __str__(self):
        str_upper = super().__str__()
        str_algorithm = f"Algorithm: {self.algorithm}\n"
        return str_upper + str_algorithm
