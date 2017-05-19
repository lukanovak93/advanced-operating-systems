from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

def Signing(data):

    private_signer_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )

    public_signer_key = private_signer_key.public_key()

    signer = private_signer_key.signer(
            padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    data_bytes = str.encode(data)

    signer.update(data_bytes)
    signature = signer.finalize()

    check = "".join([hex(h)[2:] for h in signature])
    print("From 'Signer' method: \n" + check)

    return(data_bytes, signature, public_signer_key)

def Check_sign(data_bytes, signature, public_signer_key):

    verifier = public_signer_key.verifier(
        signature,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    verifier.update(data_bytes)

    check = "".join([hex(h)[2:] for h in signature])
    print("\nFrom 'Check_sign' method: \n" + check)

    try:
        verifier.verify()
    except InvalidSignature:
        message = "Signatures are not equal!"
        return message

    message = "Signatures are equal!"
    return (message, data_bytes)

def main():
    message = "This is sent and signed by Luka Novak."
    print('\n********************************\nInitial data:\n\n>>> ' + message + '\n\n********************************\n')

    (data_b, signature, public_signer_key) = Signing(message)

    (return_message, received_data) = Check_sign(data_b, signature, public_signer_key)

    print('\nRESULT:\n********************************')
    print('Verifier verdict:\n\n>>> ' + return_message)
    print('\n\nReceived and deciphered data:\n\n>>> ' + received_data.decode("utf-8"))
    print('\n********************************\n')

if __name__ == '__main__':
    main()
