import Crypto
from Crypto.Cipher import Salsa20, AES, PKCS1_OAEP
from Crypto.Hash import BLAKE2s
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA


class ReadWriteError(Exception):
    '''Error reading or writing a file'''

#function read file (filename = path + filename)  
def read_file(filename, mode):

    try:
        with open(filename, mode) as in_file:
            read_text = in_file.read()
    except IOError as e:
        raise ReadWriteError('\nError: cannot read ' + filename + ' file: ' + str(e))

    return read_text

#function write file (filename = path + filename)
def write_file(filename, mode, txt):

    try:
        with open(filename, mode) as out_file:
            out_file.write(txt)
    except IOError as e:
        raise ReadWriteError('\nError: cannot write "ciphertext.txt" file: ' + str(e))


#function which create a key pair, one private and one public for asimetric encryption
def rsa_key_generator():

    key = RSA.generate(2048)
    return key.export_key(), key.public_key().export_key()

def save_keys(pri, pub):    

    prompt = '''\nWhere you want to save the keys (all the path + \\)
    
    -->'''

    filepath = input(prompt)

    write_file(filepath+"priv_key", "wb", pri)
    write_file(filepath+"publ_key.pub", "wb", pub)

    print("\nAll keys saved !") 

def encrypt_with_rsa():

    prompt = '''\nWhere is the public key? (path + filename)
    
    -->'''
    pub_key_location = input(prompt)

    prompt = '''\nWhich is the file you want to encrypt? (path + filename)
    
    -->'''
    plaintext_location = input(prompt)

    prompt = '''\nWhere you want to same the ciphertext? (path + \\)
    
    -->'''
    ciphertext_location = input(prompt)

    #reading the plaintext and tranform it in bytes
    plaintext = read_file(plaintext_location, "rb")

    #import the public key
    pub_key = RSA.import_key(read_file(pub_key_location, "rb"))

    #creating a session key for encrypting it with the public key
    session_key = get_random_bytes(16)
    cipher = PKCS1_OAEP.new(pub_key)
    enc_session_key = cipher.encrypt(session_key)

    cipher_aes = AES.new(session_key, AES.MODE_EAX)
    ciphertext, tag = cipher_aes.encrypt_and_digest(plaintext)

    file_out = open(ciphertext_location + 'encry.bin', 'wb')
    [ file_out.write(x) for x in (enc_session_key, cipher_aes.nonce, tag, ciphertext) ]
    file_out.close()

    print("\nENCRYPTED!")

def decrypt_with_rsa():

    prompt = '''\nWhere is the private key? (path + filename)
    
    -->'''
    pri_key_location = input(prompt)

    prompt = '''\nWhich is the file you want to decrypt? (path + filename)
    
    -->'''
    ciphertext_location = input(prompt)

    #reading the ciphertext and other things in b
    enc_message = open(ciphertext_location, "rb")

    #get the priv key for decryption
    priv_key = RSA.import_key(read_file(pri_key_location, "rb"))

    #gets the param
    enc_session_key, nonce, tag, ciphertext = [enc_message.read(x) for x in (priv_key.size_in_bytes(), 16, 16, -1)]

    #creating the cipher for decrypting the session key
    cipher = PKCS1_OAEP.new(priv_key)

    session_key = cipher.decrypt(enc_session_key)

    #creating the cipher to decrypt the ciphertext
    cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)

    plaintext = cipher_aes.decrypt_and_verify(ciphertext, tag)

    print(str(plaintext))

#main
while True:

    prompt = '''What do you want to do?
    
    1 --> Generate a Private Key and a Public Key

    2 --> Encrypt
    3 --> Decrypt
    
    0 --> Exit
    
    --> '''

    user_choice = input(prompt)

    try:
    
        if user_choice == '1':
            
            private_key, public_key = rsa_key_generator()

            save_keys(private_key, public_key)

        elif user_choice == '2':

            encrypt_with_rsa()
        
        elif user_choice == '3':
            
            decrypt_with_rsa()

        elif user_choice == '0':
            print('Goodbye')
            break
    except Exception as e:
        print(e)