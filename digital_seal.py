from digital_envelope import Encrypt, Decrypt
from digital_signature import Signing, Check_sign

import os
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding as padding_asym
from cryptography.hazmat.primitives.ciphers import (
        Cipher,
        algorithms,
        modes)

def Send_message(data, public_receiver_key):

    (cipher_key, cipher_data, init_vector) = Encrypt(data, public_receiver_key)

    (data_b, signature, public_signer_key) = Signing(data)

    return(cipher_key, cipher_data, init_vector, data_b, signature, public_signer_key)

def Receive_message(cipher_key, cipher_data, init_vector, data_b, signature, public_signer_key, private_receiver_key):

    received_data = Decrypt(private_receiver_key, cipher_key, cipher_data, init_vector)

    (return_message, received_data2) = Check_sign(data_b, signature, public_signer_key)

    return (received_data, return_message)

def main():
    private_receiver_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend())

    public_receiver_key = private_receiver_key.public_key()

    message = "This is my message and no one can't see it: 'Secret message!'. Signed by Luka Novak"
    print('\n********************************\nInitial data:\n\n>>> ' + message + '\n\n********************************\n')

    (cipher_key, cipher_data, init_vector, data_b, signature, public_signer_key) = Send_message(message, public_receiver_key)

    (received_data, return_message) = Receive_message(cipher_key, cipher_data, init_vector, data_b, signature, public_signer_key, private_receiver_key)

    print('\nRESULT:\n********************************')
    print('Verifier verdict:\n\n>>> ' + return_message)
    print('\n\nReceived and deciphered data:\n\n>>> ' + received_data.decode("utf-8"))
    print('\n********************************\n')

if __name__ == '__main__':
    main()
