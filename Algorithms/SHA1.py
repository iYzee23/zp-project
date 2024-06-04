import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend


class SHA1:
    @staticmethod
    def generate_hash(data):
        if isinstance(data, str):
            data = data.encode("utf-8")
        digest = hashes.Hash(hashes.SHA1(), backend=default_backend())
        digest.update(data)
        return base64.b64encode(digest.finalize()).decode("utf-8")

    @staticmethod
    def compare_hashes(hash1, hash2):
        return hash1 == hash2
