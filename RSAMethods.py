from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP


def decrypt(req):
    file_out = open("encrypted_data.txt", "wb")
    file_out.write(req)
    file_out.close()
    file_in = open("encrypted_data.txt", "rb")

    private_key = RSA.import_key(open("private.pem").read())

    enc_session_key, nonce, tag, ciphertext = \
        [file_in.read(x) for x in (private_key.size_in_bytes(), 16, 16, -1)]

    # Decrypt the session key with the private RSA key
    cipher_rsa = PKCS1_OAEP.new(private_key)
    session_key = cipher_rsa.decrypt(enc_session_key)

    # Decrypt the data with the AES session key
    cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
    data = cipher_aes.decrypt_and_verify(ciphertext, tag)
    file_in.close()
    open('encrypted_data.txt', 'w').close()
    return data.decode("utf-8")
