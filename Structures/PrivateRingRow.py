from PublicRingRow import PublicRingRow


class PrivateRingRow(PublicRingRow):
    def __init__(self, public_key, private_key, password, name, mail, algorithm):
        super().__init__(public_key, name, mail)
        self.algorithm = algorithm
        self.hashed_password = self.hash_password(password)
        self.encrypted_private_key = self.encrypt_key(private_key, password)

    def get_private_key(self, password):
        hashed_password = self.hash_password(password)
        if hashed_password == self.hashed_password:
            pass
        return None

    def hash_password(self, password):
        pass

    def encrypt_private_key(self, private_key, password):
        pass

    def decrypt_private_key(self, enc_private_key, password):
        pass

    def __str__(self):
        str_upper = super().__str__()
        str_algorithm = f"Algorithm: {self.algorithm}\n"
        return str_upper + str_algorithm
