# import cryptography modules
from Crypto.Cipher import ChaCha20, AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import scrypt

from getpass import getpass
import string
import re

alph = list(string.printable)


''' ---- Exception Manage ----'''
class CypherException(Exception):
    pass

class MainException(Exception):
    pass

class SelectionErrorException(Exception):
    pass

class PasswordErrorException(Exception):
    pass
    
    
''' ---- IO Manage ----'''
# Write a file
def read_file(prompt, validate=None):
    # repeat until a validated input is read or user aborts
    while True:
        # acquire file path
        path = input(prompt)
        # read input managing IOErrors
        try:
            # read content as bytes
            with open(path, 'rb') as in_file:
                content = in_file.read()
            # if no validation return content
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
            print('Error: Cannot read file ' + path + ': ' + str(e))
        # no valid content read: try again or abort
        choice = input('(q to abort, anything else to try again) ')
        if choice == 'q':
            raise CypherException('Input aborted')

# function that handles file output
# parameters:
# - prompt: message to display acquiring file path
# - data: bytes to be written in file
# tries to write data until success or user aborts


def write_file(prompt, data):
    # repeat until successful write or user aborts
    while True:
        # acquire file path
        path = input(prompt)
        # write input managing IOErrors
        try:
            # write content as bytes
            with open(path, 'wb') as out_file:
                out_file.write(data)
            return 'Data successfully written in file "' + path + '".'
        except IOError as e:
            print('Error: Cannot write file ' + path + ': ' + str(e))
        # write insuccesful: try again or abort
        choice = input('(q to abort, anything else to try again) ')
        if choice == 'q':
            raise CypherException('Output aborted')
        
        
# Check length of the data
def check_c_len(data, c_len): 
    if(len(data)) >= c_len:
        return ""
    else: 
        return "Error: Ciphertext must be at least " + str(c_len) + " bytes long."

def check_k_len(data, k_len):
    if len(data) == k_len:
        return ''
    else:
        return 'Error: the key must be exactly ' + k_len + ' bytes long.'


def gen_prompt(f_type, reading):
    message = "Please insert path of the file "
    if reading:
        message += "that contains the " + f_type
    else:
        message += "where to save the " + f_type
    return message + ": "



def generatePassword():
    print('Insert your password below: \n')
    try:
        passwd = getpass()
        regex = re.compile('[^\w\*]')
        
        if len(passwd) < 8:
            raise PasswordErrorException("Password troppo corta!")
        else:
            return passwd
        # elif regex.search(passwd) == None:
        #     return passwd
        # else:
        #     raise PasswordErrorException("Password deve avere almeno un carattere speciale!")
    
    except UserWarning as err:
        print('ERRORE:', err)


'''  ---- Encode & Decode ---- '''
def encrypt(auth):
    # read file to encrypt, no validation
    p_data = read_file(gen_prompt("data to encrypt", True))
    # encryption
    # TODO: Riprogramamre la key
    if auth:
        salt = get_random_bytes(16)
        key = scrypt(generatePassword(), salt, 16, N=2**14, r=8, p=1)
        
        cipher = AES.new(key, AES.MODE_GCM)
        ciphertext, tag = cipher.encrypt_and_digest(p_data)
        c_data = salt + cipher.nonce + tag + ciphertext
    else:
        salt = get_random_bytes(16)
        
        key = scrypt(generatePassword(), salt, 16, N=2**14, r=8, p=1)
        cipher = ChaCha20.new(key=key)
        ciphertext = cipher.encrypt(p_data)
        c_data = salt + cipher.nonce + ciphertext
    # output
    print(write_file(gen_prompt("encrypted data", False), c_data))
    
    
def decrypt(auth):
    if auth:
        # read key validating its length
        # read ciphertext validating its length
        c_data = read_file(gen_prompt("data to decrypt", True), lambda data: check_c_len(data, 32))
        
        # decryption
        key = scrypt(generatePassword(), c_data[:16], 16, N = 2**14, r = 8, p = 1)
        
        
        nonce = c_data[16:32]
        tag = c_data[32:48]
        ciphertext = c_data[48:]
        cipher = AES.new(key, AES.MODE_GCM, nonce)
        try:
            p_data = cipher.decrypt_and_verify(ciphertext, tag)
        except ValueError:
            raise CypherException('Decryption error: authentication failure')
    else:
        # read ciphertext validating its length
        c_data = read_file(gen_prompt("data to decrypt", True), lambda data: check_c_len(data, 8))
        
        # read key validating its length
        key = scrypt(generatePassword(), c_data[:16], 16, N = 2**14, r = 8, p = 1)
        
        # decryption
        nonce = c_data[16:24]
        ciphertext = c_data[24:]
        cipher = ChaCha20.new(key = key, nonce = nonce)
        p_data = cipher.decrypt(ciphertext)
    # output
    print(write_file(gen_prompt("decrypted data", False), p_data))



def authenticate():
    prompt = 'Do you want to perform authentication? (y/n) '
    while True:
        choice = input(prompt)
        if choice == 'y':
            return True
        elif choice == 'n':
            return False
        else:
            print('Invalid choice, please try again!')


''' ---- MAIN ---- '''
if __name__ == '__main__':
    while True:
        prompt = '''What do you want to do?
    1 -> Encrypt message.
    2 -> Decrypt message.
    
    0 -> Exit.
--> '''

        choice = input(prompt)
        try:
            if choice == '1':
                encrypt(authenticate())
            elif choice == '2':
                decrypt(authenticate())
            elif choice == '0':
                break
            else:
                print('Invalid choice, please try again!')
                
        except MainException as e:
            print(e)