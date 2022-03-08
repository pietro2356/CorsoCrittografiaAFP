from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.PublicKey import RSA, ECC
from Crypto.Hash import SHA3_256
from Crypto.Random import get_random_bytes
from getpass import getpass
from os.path import isfile
from base64 import b64encode
import json


CA_CERT_AUTH = ECC.import_key('')