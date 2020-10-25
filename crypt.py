# -*- coding: utf-8 -*-
import pathlib
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP
import os, sys

DIR = str(pathlib.Path(__file__).parent.absolute())

receiver_file = DIR + '/receiver.pem'
private_file = DIR + '/private.pem'


def generateKeys():
    key = RSA.generate(2048)
    file_out = open(private_file, 'wb')
    file_out.write(key.exportKey('PEM'))
    print('private generated')

    file_out = open(receiver_file, 'wb')
    file_out.write(key.publickey().exportKey('PEM'))
    print('public generated')


if not os.path.isfile(receiver_file) or not os.path.isfile(private_file):
    generateKeys()


class cryptor:
    @staticmethod
    def crypt(file):
        f = open(file, 'rb')
        data = f.read()
        f.close()

        file_out = open(str(file) + '.bin', 'wb')

        recipient_key = RSA.import_key(open(receiver_file).read())
        session_key = get_random_bytes(16)

        cipher_rsa = PKCS1_OAEP.new(recipient_key)
        enc_session_key = cipher_rsa.encrypt(session_key)

        cipher_aes = AES.new(session_key, AES.MODE_EAX)
        ciphertext, tag = cipher_aes.encrypt_and_digest(data)

        for x in (enc_session_key, cipher_aes.nonce, tag, ciphertext):
            file_out.write(x)

        print(file + ' ЗАШИФРОВАН!')
        os.remove(file)

    @staticmethod
    def walk(dir):
        for name in os.listdir(dir):
            path = os.path.join(dir, name)
            if os.path.isfile(path):
                cryptor.crypt(path)
            else:
                cryptor.walk(path)


print(DIR + '/result')

if input('Напигите 1 если вы точно хотите закриптовать эту директорию: ') == '1':
    cryptor.walk(DIR + '/result')
print('---------------------------------------------------------------')
