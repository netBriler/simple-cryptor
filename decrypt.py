# -*- coding: utf-8 -*-
import pathlib
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
import os

DIR = str(pathlib.Path(__file__).parent.absolute())

private_file = DIR + '/private.pem'


class decryptor:
    @staticmethod
    def decrypt(file):
        try:
            private_key = RSA.import_key(open(private_file).read())
        except:
            print('Ключ фальшивный')
            return exit(403)

        file_in = open(file, 'rb')
        file_out = open(str(file[:-4]), 'wb')

        enc_session_key, nonce, tag, ciphertext = \
            [file_in.read(x) for x in (private_key.size_in_bytes(), 16, 16, -1)]

        cipher_rsa = PKCS1_OAEP.new(private_key)
        session_key = cipher_rsa.decrypt(enc_session_key)

        cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
        data = cipher_aes.decrypt_and_verify(ciphertext, tag)
        file_in.close()
        file_out.write(data)
        print(file + ' РАСШИФРОВАН!')
        os.remove(file)

    @staticmethod
    def walk(dir):
        for name in os.listdir(dir):
            path = os.path.join(dir, name)
            if os.path.isfile(path):
                decryptor.decrypt(path)
            else:
                decryptor.walk(path)


print(DIR + '/result')

if input('Напигите 1 если вы точно хотите роззакриптовать эту директорию: ') == '1':
    decryptor.walk(DIR + '/result')
print('---------------------------------------------------------------')
