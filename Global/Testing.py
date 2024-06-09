import secrets
import os
import datetime
from Algorithms.FileUtil import FileUtil
from Algorithms.RSA import RSA
from Algorithms.AES128 import AES128
from Algorithms.DES3 import DES3
from Structures.Message import Message
from Structures.Options import Options
from Global.Variables import private_rings, public_rings


def test_imports_exports():
    # export txt
    # message_txt = "Txt fajl"
    # FileUtil.export_message(message_txt)

    # import txt
    message_txt = FileUtil.import_message()
    print(message_txt)

    # export pem
    message_pem = "Pem fajl"
    FileUtil.export_pem(message_pem, "PRIVATE_KEY")

    # import pem
    message_pem = FileUtil.import_pem("PRIVATE_KEY")
    print(message_pem)


def test_rsa():
    (public_key, private_key) = RSA.generate_keys(1024)
    message = "Hello World"
    cyphertext = RSA.encrypt_message(message, public_key)
    print(cyphertext)
    original_message = RSA.decrypt_message(cyphertext, private_key)
    print(original_message)
    RSA.export_public_tk(public_key)
    print(RSA.import_public_tk())
    RSA.export_keys_tk(public_key, private_key)
    print(RSA.import_keys_tk())


def test_aes128():
    # key = os.urandom(16)
    key = secrets.token_bytes(16)
    message = "Hello World"
    cyphertext = AES128.encrypt_message(message, key)
    print(cyphertext)
    original_message = AES128.decrypt_message(cyphertext, key)
    print(original_message)


def test_des3():
    # key = os.urandom(24)
    key = secrets.token_bytes(24)
    message = "Hello World"
    cyphertext = DES3.encrypt_message(message, key)
    print(cyphertext)
    original_message = DES3.decrypt_message(cyphertext, key)
    print(original_message)


def test_message_sending(enc, auth, compr, radix, alg, sender, sender_key_id, recipient_key_id, cnt):
    data = "Saljem veliki pozdrav svim dobrim ljudima ovog sveta! :)"
    filename = "file.txt"
    timestamp = datetime.datetime.now()
    options = Options(enc, auth, compr, radix, alg)
    message = Message(data, filename, timestamp, options)

    sender_private_row = private_rings[sender].get_row(sender_key_id)
    recipient_public_row = public_rings[sender].get_row(recipient_key_id)
    msg = Message.send_message(message, sender_private_row, "pesic123", recipient_public_row)

    # FileUtil.export_message(msg)
    with open(f"Tests/{alg}_{cnt}.txt", 'w') as file:
        file.write(msg)
        file.close()


def test_message_receiving(recipient, recipient_key_id, sender_key_id, alg, cnt):
    pass
    # msg = FileUtil.import_message()
    # with open(f"Tests/{alg}_{cnt}.txt", 'r') as file:
    #     msg = file.read()
    #     file.close()
    #
    # recipient_private_row = private_rings[recipient].get_row(recipient_key_id)
    # sender_public_row = public_rings[recipient].get_row(sender_key_id)
    # message = Message.receive_message(msg, recipient_private_row, "nevajda123", sender_public_row)
    # print(message)


def test_message_flow(enc, auth, compr, radix, alg, cnt):
    sender = "Pesic###pesic@etf.rs"
    recipient = "Nevajda###nevajda@etf.rs"
    for row in private_rings[sender].get_rows().values():
        sender_key_id = row.key_id
        break
    for row in private_rings[recipient].get_rows().values():
        recipient_key_id = row.key_id
        break
    test_message_sending(enc, auth, compr, radix, alg, sender, sender_key_id, recipient_key_id, cnt)
    test_message_receiving(recipient, recipient_key_id, sender_key_id, alg, cnt)


def test_message_flow_all_variants():
    cnt = 0
    for enc in [True, False]:
        for auth in [True, False]:
            for compr in [True, False]:
                for radix in [True, False]:
                    cnt += 1
                    for alg in ["AES128", "DES3"]:
                        test_message_flow(enc, auth, compr, radix, alg, cnt)


def test_keys_generation():
    keys = []
    keys.append(RSA.generate_keys(1024))
    keys.append(RSA.generate_keys(2048))
    keys.append(RSA.generate_keys(1024))
    keys.append(RSA.generate_keys(2048))
    keys.append(RSA.generate_keys(1024))
    keys.append(RSA.generate_keys(2048))
    keys.append(RSA.generate_keys(1024))
    keys.append(RSA.generate_keys(2048))
    keys.append(RSA.generate_keys(1024))
    keys.append(RSA.generate_keys(2048))
    keys.append(RSA.generate_keys(1024))
    keys.append(RSA.generate_keys(2048))
    keys.append(RSA.generate_keys(1024))
    keys.append(RSA.generate_keys(2048))
    keys.append(RSA.generate_keys(1024))
    keys.append(RSA.generate_keys(2048))
    keys.append(RSA.generate_keys(1024))
    keys.append(RSA.generate_keys(2048))
    keys.append(RSA.generate_keys(1024))
    keys.append(RSA.generate_keys(2048))
    keys.append(RSA.generate_keys(1024))
    keys.append(RSA.generate_keys(2048))
    keys.append(RSA.generate_keys(1024))
    keys.append(RSA.generate_keys(2048))
    keys.append(RSA.generate_keys(1024))
    keys.append(RSA.generate_keys(2048))

    for i in range(26):
        public_key = keys[i][0]
        private_key = keys[i][1]
        RSA.export_keys(public_key, private_key, i + 1)
        RSA.export_public(public_key, i + 1)


def test_public_private_rings():
    for private_ring in private_rings.values():
        print(private_ring)
        print()

    for public_ring in public_rings.values():
        print(public_ring)
        print()
