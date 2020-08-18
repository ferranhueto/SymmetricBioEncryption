import os
import base64

from cryptography.fernet import Fernet
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


BYTE_ENCODING = "utf-8"
INPUT_FILE = "input.txt"
DB_FILE = "db.txt"

def get_input_encodings(filename):
    """
    Get input hash bioencodings from input textfile.
    return: encoding_1, encoding_2
    rtype: string, string
    """
    f = open(filename, "r")
    encoding_1, encoding_2 = (e for e in f.read().split(","))
    return encoding_1, encoding_2

def generate_key_from_encoding(encoding, salt=b"0"):
    """
    Generate key from string encoding using HMAC algorithm
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(bytes(encoding, BYTE_ENCODING)))
    return key

def generate_encrypted_encoding(encoding, key):
    """
    Generate encrypted encoding from encoding and key, using Fernet algorithm.
    return: hash_encoding
    rtype: string
    """
    cipher_suite = Fernet(key)
    hash_encoding = cipher_suite.encrypt(bytes(encoding, BYTE_ENCODING))
    return hash_encoding

def main():
    """
    Fetch and display payment information from Symmetric Bioencrypted database
    """
    encoding_1, encoding_2 = get_input_encodings("input.txt")
    key, encoding = generate_key_from_encoding(encoding_1), encoding_2
    print(key)
    hash_encoding = generate_encrypted_encoding(encoding_2, key)
    # print(hash_encoding)





if __name__ == '__main__':
    main()
