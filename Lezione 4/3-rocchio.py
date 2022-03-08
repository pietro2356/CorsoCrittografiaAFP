from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA


class IOExceptionError(Exception):
    '''Error reading or writing a file'''
    
class CypherException(Exception):
    pass

class MainException(Exception):
    pass

class SelectionErrorException(Exception):
    pass

class PasswordErrorException(Exception):
    pass

#function read file (filename = path + filename)  
def read_file(filename:str, mode:str, validate = None):

    try:
        with open(filename, mode) as in_file:
            content = in_file.read()
        
        if validate == None:
            return content
        # else validate content
        val_err = validate(content)
        if val_err == '':
            # validation succesful, return content (end of function)
            return content
        # print validation error
        print(val_err)
    except IOError as e:
        raise IOExceptionError('\nError: cannot read ' + filename + ' file: ' + str(e))

    return content

#function write file (filename = path + filename)
def write_file(filename:str, mode:str, txt):
    try:
        with open(filename, mode) as out_file:
            out_file.write(txt)
        return 'Data successfully written in file "' + filename + '".'
    except IOError as e:
        raise IOExceptionError('\nError: cannot read ' + filename + ' file: ' + str(e))


#function which create a key pair, one private and one public for asimetric encryption
def generateKey():
    key = RSA.generate(4096)
    return key.export_key(), key.public_key().export_key()

def saveKeys(pri, pub):    
    filepath = input("Where you want to save your keys: ")

    write_file(filepath + "priv_key", "wb", pri)
    write_file(filepath + "pub_key.pub", "wb", pub)

    print("\nAll keys saved !") 

def encrypt():
    pub_key_location = input("Where is the public key? (path + filename)")
    plaintext_location = input("Which is the file you want to encrypt? (path + filename")
    ciphertext_location = input("Where you want to same the ciphertext? (path + \\)")

    plaintext = read_file(plaintext_location, "rb")

    pub_key = RSA.import_key(read_file(pub_key_location, "rb"))

    session_key = get_random_bytes(16)
    cipher = PKCS1_OAEP.new(pub_key)
    enc_session_key = cipher.encrypt(session_key)

    cipher_aes = AES.new(session_key, AES.MODE_EAX)
    ciphertext, tag = cipher_aes.encrypt_and_digest(plaintext)

    file_out = open(ciphertext_location + '.bin', 'wb')
    [ file_out.write(x) for x in (enc_session_key, cipher_aes.nonce, tag, ciphertext) ]
    file_out.close()

    print("Encrypt completed successfully!")

def decrypt():
    pri_key_location = input("Where is the private key? (path + filename)")
    ciphertext_location = input("Which is the file you want to decrypt? (path + filename)")

    enc_message = open(ciphertext_location, "rb")
    priv_key = RSA.import_key(read_file(pri_key_location, "rb"))
    enc_session_key, nonce, tag, ciphertext = [enc_message.read(x) for x in (priv_key.size_in_bytes(), 16, 16, -1)]
    cipher = PKCS1_OAEP.new(priv_key)
    session_key = cipher.decrypt(enc_session_key)
    cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
    plaintext = cipher_aes.decrypt_and_verify(ciphertext, tag)

    print("Decription completed successfully!")
    print("Plaintext: " + str(plaintext))




''' ---- MAIN ---- '''
if __name__ == '__main__':
    while True:
        prompt = '''What do you want to do?
    1 -> Generate a key.
    2 -> Encrypt message.
    3 -> Decrypt message.
    
    0 -> Exit.
--> '''

        choice = input(prompt)
        try:
            if choice == '1':
                privKey, pubKey = generateKey()
                saveKeys(privKey, pubKey)
            elif choice == '2':
                encrypt()
            elif choice == '3':
                decrypt()
            elif choice == '0':
                print("Exiting...")
                break
            else:
                print('Invalid choice, please try again!')
                
        except MainException as e:
            print(e)