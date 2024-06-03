from Algorithms.FileUtil import FileUtil
from Algorithms.RSA import RSA
from Algorithms.AES128 import AES128
from Algorithms.DES3 import DES3
import os
def test_imports_exports():
    # export txt
    message_txt = "Txt fajl"
    FileUtil.export_message(message_txt)

    # import txt
    message_txt = FileUtil.import_message()
    print(message_txt)

    # export pem
    message_pem = "Pem fajl"
    FileUtil.export_pem(message_pem, "PRIVATE_KEY")

    # import pem
    message_pem = FileUtil.import_pem("PRIVATE_KEY")
    print(message_pem)

def test_RSA():
    (public_key, private_key)=RSA.generate_key(1024)
    message = "Hello World"
    cyphertext=RSA.encrypt_message(message, public_key)
    print(cyphertext)
    original_message=RSA.decrypt_message(cyphertext, private_key)
    print(original_message)
    RSA.export_public(public_key)
    print(RSA.import_public())
    RSA.export_key((public_key, private_key))
    print(RSA.import_key())

def test_AES128():
    key=os.urandom(16)
    message="Hello World"
    cyphertext=AES128.encrypt_message(message,key)
    print(cyphertext)
    original_message=AES128.decrypt_message(cyphertext,key)
    print(original_message)

def test_DES3():
    key = os.urandom(24)
    message = "Hello World"
    cyphertext = DES3.encrypt_message(message, key)
    print(cyphertext)
    original_message = DES3.decrypt_message(cyphertext, key)
    print(original_message)
