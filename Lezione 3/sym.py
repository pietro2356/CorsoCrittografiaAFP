# --Symmetric Encryption--

# import cryptography modules
from Crypto.Cipher import ChaCha20, AES
from Crypto.Random import get_random_bytes

# custom error


class SymEncError(Exception):
    '''Error executing Symmetric Encryption script'''

# function that handles file input
# parameters:
# - prompt: message to display acquiring file path
# - validate: function that validates content read
# tries to read valid content until success or user aborts


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
            raise SymEncError('Input aborted')

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
            raise SymEncError('Output aborted')

# function that generates prompts for reading and writing files
# parameters:
# - f_type: string that describes the file
# - read: boolean that tells if the prompt is for input or not


def gen_prompt(f_type, reading):
    message = "Please insert path of the file "
    if reading:
        message += "that contains the " + f_type
    else:
        message += "where to save the " + f_type
    return message + ": "

# function that performs encryption
# parameters:
# auth: boolean that tells whether to perform authentication


def encrypt(auth):
    # read file to encrypt, no validation
    p_data = read_file(gen_prompt("data to encrypt", True))
    # encryption
    if auth:
        key = get_random_bytes(16)
        cipher = AES.new(key, AES.MODE_GCM)
        ciphertext, tag = cipher.encrypt_and_digest(p_data)
        c_data = cipher.nonce + tag + ciphertext
    else:
        key = get_random_bytes(32)
        cipher = ChaCha20.new(key=key)
        ciphertext = cipher.encrypt(p_data)
        c_data = cipher.nonce + ciphertext
    # output
    print(write_file(gen_prompt("key", False), key))
    print(write_file(gen_prompt("encrypted data", False), c_data))

# function that validates key length
# parameters:
# data: byte string to check
# k_len: length in bytes the key must have


def check_k_len(data, k_len):
    if len(data) == k_len:
        return ''
    else:
        return 'Error: the key must be exactly ' + k_len + ' bytes long.'

# function that validates ciphertext file length
# parameters:
# data: byte string to check
# c_len: length in bytes the key must have


def check_c_len(data, c_len):
    if len(data) >= c_len:
        return ''
    else:
        return 'Error: the ciphertext must be at least ' + c_len + ' bytes long.'


# function that performs decryption
# parameters:
# auth: boolean that tells whether to perform authentication


def decrypt(auth):
    if auth:
        # read key validating its length
        key = read_file(gen_prompt("key", True),
                        lambda data: check_k_len(data, 16))
        # read ciphertext validating its length
        c_data = read_file(gen_prompt("data to decrypt", True),
                           lambda data: check_c_len(data, 32))
        # decryption
        nonce = c_data[:16]
        tag = c_data[16:32]
        ciphertext = c_data[32:]
        cipher = AES.new(key, AES.MODE_GCM, nonce)
        try:
            p_data = cipher.decrypt_and_verify(ciphertext, tag)
        except ValueError:
            raise SymEncError('Decryption error: authentication failure')
    else:
        # read key validating its length
        key = read_file(gen_prompt("key", True),
                        lambda data: check_k_len(data, 32))
        # read ciphertext validating its length
        c_data = read_file(gen_prompt("data to decrypt", True),
                           lambda data: check_c_len(data, 8))
        # decryption
        nonce = c_data[:8]
        ciphertext = c_data[8:]
        cipher = ChaCha20.new(key=key, nonce=nonce)
        p_data = cipher.decrypt(ciphertext)
    # output
    print(write_file(gen_prompt("decrypted data", False), p_data))

# function that asks the user whether to perform authentication


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


# main
main_prompt = '''What do you want to do?
1 -> encrypt
2 -> decrypt
0 -> quit
-> '''

while True:
    # get user's choice and call appropriate function
    # errors are captured and printed out
    choice = input(main_prompt)
    try:
        if choice == '1':
            encrypt(authenticate())
        elif choice == '2':
            decrypt(authenticate())
        elif choice == '0':
            exit()
        else:
            # default error message for wrong inputs
            print('Invalid choice, please try again!')
    except SymEncError as e:
        print(e)