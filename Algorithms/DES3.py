import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding


class DES3:
    @staticmethod
    def encrypt_message(message, key):
        cipher = Cipher(algorithms.TripleDES(key), modes.ECB(), backend=default_backend())
        encryptor = cipher.encryptor()

        padder = padding.PKCS7(algorithms.TripleDES.block_size).padder()
        padded_data = padder.update(message.encode("utf-8")) + padder.finalize()

        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        return base64.b64encode(ciphertext).decode("utf-8")

    @staticmethod
    def decrypt_message(ciphertext, key):
        ciphertext = base64.b64decode(ciphertext.encode("utf-8"))
        cipher = Cipher(algorithms.TripleDES(key), modes.ECB(), backend=default_backend())
        decryptor = cipher.decryptor()

        decrypted_padded_data = decryptor.update(ciphertext) + decryptor.finalize()

        unpadder = padding.PKCS7(algorithms.TripleDES.block_size).unpadder()
        decrypted_data = unpadder.update(decrypted_padded_data) + unpadder.finalize()
        return decrypted_data.decode("utf-8")
