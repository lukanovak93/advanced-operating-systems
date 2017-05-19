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


def Encrypt(data, public_receiver_key):
    key = os.urandom(32)
    init_vector = os.urandom(16)

    cipher_aes = Cipher(algorithms.AES(key),
                    modes.CBC(init_vector),
                    backend=default_backend())

    data_bytes = str.encode(data)

    # add padding to plain text
    padder = padding.PKCS7(128).padder() # 128 bit
    padded_data = padder.update(data_bytes) + padder.finalize()

    # encrypt data
    data_encryptor = cipher_aes.encryptor()
    cipher_data = data_encryptor.update(padded_data) + data_encryptor.finalize()

    cipher_data_print = "".join([hex(h)[2:] for h in cipher_data])
    print(cipher_data_print)

    # encrypt encriptor's key
    cipher_key = public_receiver_key.encrypt(
        key,
        padding_asym.OAEP(
            mgf=padding_asym.MGF1(algorithm=hashes.SHA1()),
            algorithm=hashes.SHA1(),
            label=None
        )
    )

    return (cipher_key, cipher_data, init_vector)

def Decrypt(private_receiver_key, cipher_key, cipher_data, init_vector):

    key = private_receiver_key.decrypt(
        cipher_key,
        padding_asym.OAEP(
            mgf=padding_asym.MGF1(algorithm=hashes.SHA1()),
            algorithm=hashes.SHA1(),
            label=None
        )
    )

    cipher_aes = Cipher(algorithms.AES(key),
                    modes.CBC(init_vector),
                    backend=default_backend())

    # decrypt plain text with padding
    decryptor = cipher_aes.decryptor()
    deciphered_data = decryptor.update(cipher_data) + decryptor.finalize()

    # remove padding
    unpadder = padding.PKCS7(128).unpadder() # 128 bit
    return_data = unpadder.update(deciphered_data) + unpadder.finalize()
    return return_data

def main():

    private_receiver_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend())

    public_receiver_key = private_receiver_key.public_key()

    text = "A secret message that must not be deciphered!"
    print('\n********************************\n\nInitial data:\n\n>>> ' + str(text) + '\n\n********************************\n')

    (cipher_key, cipher_data, init_vector) = Encrypt(text, public_receiver_key)

    received_data = Decrypt(private_receiver_key, cipher_key, cipher_data, init_vector)
    print('\nRESULT:\n********************************\n\nReceived and deciphered data:\n\n>>> ' + received_data.decode("utf-8") + '\n\n********************************\n')

if __name__ == '__main__':
    main()
