# --Hybrid Encryption--

# import cryptography modules
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from getpass import getpass
from os.path import isfile

# custom errors


class HybEncError(Exception):
    '''Error executing Hybrid Encryption script'''

class ReadProcessingError(HybEncError):
  '''Error preprocessing data read from file'''


#
# INPUT/OUTPUT functions
#


# funtion that reads files
# parameters:
# - subject: what the file should contain
# - error: error message to show when aborting
# - default: name of file to open if not specified
# - process: function to call on data,
#       reading is not considered complete unless
#       this function is called successfully.
#       Should raise ReadProcessingError on errors
# returns data read (and processed) and name of file read


def read_file(subject, error, default='', process=lambda data: data):
    #prepare string to print, including default choice
    prompt = 'Insert path to ' + subject + ' file'
    if default != '':
        prompt += ' (' + default + ')' 
    prompt += ':\n'
    #try until file is correctly read or user aborts
    while True:
        #read choice, use default if empty
        in_filename = input(prompt)
        if in_filename  == '':
            in_filename  = default
        #read and process data
        try:
            with open(in_filename, 'rb') as in_file:
                data = in_file.read()
            return process(data), in_filename
        except (IOError, ReadProcessingError) as e:
            print('Error while reading '+subject+':\n'+str(e))
            #let user abort reading file
            c = input('q to quit, anything else to try again: ')
            if c.lower() == 'q':
                #abort
                raise HybEncError(error)

# function to write on file
# parameters:
# - data: what to write to file
# - subject: description of what the file will contain
# - error: error message to show when aborting
# - default: name of file to open if not specified
# returns name of file written


def write_file(data, subject, error, default=''):  
    #try until file is correctly written or user aborts
    while True:
        # prepare string to print, including default choice
        prompt = 'Insert path to file where to save ' + subject
        if default != '':
            prompt += ' (' + default + ')' 
        prompt += ':\n'
        # read choice, use default if empty
        out_filename = input(prompt)
        if out_filename  == '':
            out_filename  = default
        try:
            # warn before overwriting
            if isfile(out_filename):
                prompt = 'File exists, overwrite? '
                prompt += '(n to cancel, anything else to continue)\n'
                overwrite = input(prompt)
                if overwrite.lower() == 'n':
                    continue
            # write data
            with open(out_filename, 'wb') as out_file:
                out_file.write(data)
            return out_filename
        except IOError as e:
            print('Error while saving '+subject+': '+str(e))
            # let user abort writing file
            c = input('q to quit, anything else to try again: ')
            if c.lower() == 'q':
                # abort
                raise HybEncError(error)



#
# VALIDATION FUNCTIONS
#


# function that validates ciphertext file length
# parameters:
# data: byte string to check
# c_len: length in bytes the key must have


def check_c_len(data, c_len):
    if len(data) >= c_len:
        return data
    else:
        message = 'Error: the ciphertext must be at least '
        message += str(c_len) + ' bytes long.'
        raise ReadProcessingError(message)


# function that validates an RSA key
# parameters:
# - data: byte string to check
# - private: boolean that tells if the key should be a private key


def import_key(data, private):
    passphrase = None
    if private:
        # aquire passphrase
        passphrase = getpass("Insert password to unlock the private key:")
    # import key
    try:
        key = RSA.import_key(data, passphrase=passphrase)
    except (ValueError, IndexError, TypeError) as e:
        # error message
        message = 'Error while importing the key: ' + str(e)
        if private:
            message += '\nPlease check that the password is correct.'
        raise ReadProcessingError(message)
    # check size
    if key.size_in_bytes() < 256:
        message = 'Error: the key should be at least 2048 bits long!'
        raise ReadProcessingError(message)
    # check type
    if private and (not key.has_private()):
        raise ReadProcessingError('Error: this is not a private key!')
    
    return key



# function that acquires a non-empty passphrase
# for private key protection

def get_passphrase():
    prompt = "Insert password for the private key:"
    while True:
        pw = getpass(prompt)
        if pw != '':
            return pw
        else:
            prompt = "please enter a non-empty password:"


#
# MAIN LOGIC FUNCTIONS
#


# function that generates an RSA key pair


def gen_keys():
    # generate key pair
    key = RSA.generate(2048)
    print('Keys generated!')
    # export private key
    # acquire passphrase
    passphrase = get_passphrase()
    #define export settings
    export_settings = {
        'format': 'PEM',
        'passphrase': passphrase,
        'protection': 'scryptAndAES128-CBC'
    }
    # export
    private_key = key.export_key(**export_settings)    
    # save on file
    settings = {
        'data': private_key,
        'subject': 'private key',
        'error': 'Output aborted.',
        'default': 'sk.pem'
    }
    out_file = write_file(**settings)
    print('Private key correctly written in "' + out_file + '"')
    # export public key
    public_key = key.public_key().export_key()
    # save on file
    settings = {
        'data': public_key,
        'subject': 'public key',
        'error': 'Output aborted.',
        'default': 'pk.pem'
    }
    out_file = write_file(**settings)
    print('Public key correctly written in "' + out_file + '"')



# function that performs encryption


def encrypt():
    # read public key to use
    settings = {
        'subject': 'public key',
        'error': 'Key import aborted.',
        'default': 'pk.pem',
        'process': lambda data: import_key(data, False)
    }
    rsa_pk, _ = read_file(**settings)

    # read file to encrypt, no validation
    settings = {
        'subject': 'data to encrypt',
        'error': 'Plaintext reading aborted.'
    }
    
    p_data, in_file = read_file(**settings)

    # file encryption
    aes_key = get_random_bytes(16)
    aes_cipher = AES.new(aes_key, AES.MODE_OCB)
    ciphertext, tag = aes_cipher.encrypt_and_digest(p_data)
    # key encryption
    # errors not captured because of previous checks on pk
    rsa_cipher = PKCS1_OAEP.new(rsa_pk)
    enc_key = rsa_cipher.encrypt(aes_key)
    # output 
    settings = {
        'data': enc_key + aes_cipher.nonce + tag + ciphertext,
        'subject': 'ciphertext',
        'error': 'Output aborted.',
        'default': in_file + '.enc'
    }
    out_file = write_file(**settings)
    print('Ciphertext correctly written in "' + out_file + '"')



# function that performs decryption


def decrypt():
    # read private key to use
    settings = {
        'subject': 'private key',
        'error': 'Key import aborted.',
        'default': 'sk.pem',
        'process': lambda data: import_key(data, True)
    }
    rsa_sk, _ = read_file(**settings)

    # read file to decrypt, validating length
    rsa_size = rsa_sk.size_in_bytes()
    min_c_len = rsa_size + 15 + 16
    settings = {
        'subject': 'data to decrypt',
        'error': 'Ciphertext reading aborted.',
        'process': lambda data: check_c_len(data, min_c_len)
    }
    c_data, in_file = read_file(**settings)
    # decomposition
    enc_key = c_data[ : rsa_size]
    nonce = c_data[rsa_size : rsa_size+ 15]
    tag = c_data[rsa_size + 15: min_c_len]
    ciphertext = c_data[min_c_len : ]

    # key decryption
    # some errors are not captured because of previous checks on sk
    rsa_cipher = PKCS1_OAEP.new(rsa_sk)
    try:
        aes_key = rsa_cipher.decrypt(enc_key)
    except ValueError:
        raise HybEncError('Decryption error: please check private key')
    # ciphertext decryption
    aes_cipher = AES.new(aes_key, AES.MODE_OCB, nonce)
    try:
        p_data = aes_cipher.decrypt_and_verify(ciphertext, tag)
    except ValueError:
        raise HybEncError('Decryption error: authentication failure')    
    # output
    # try to deduce original filename
    if in_file[-4:] == '.enc':
        default = in_file[:-4]
    else:
        default = ''
    # write output
    settings = {
        'data': p_data,
        'subject': 'decrypted data',
        'error': 'Output aborted.',
        'default': default
    }
    out_file = write_file(**settings)
    print('Decrypted data correctly written in "' + out_file + '"')



#
# MAIN
#

main_prompt = '''What do you want to do?
1 -> generate a new RSA key pair
2 -> encrypt
3 -> decrypt
0 -> quit
-> '''

while True:
    # get user's choice and call appropriate function
    # errors are captured and printed out
    choice = input(main_prompt)
    try:
        if choice == '1':
            gen_keys()
        elif choice == '2':
            encrypt()
        elif choice == '3':
            decrypt()
        elif choice == '0':
            exit()
        else:
            # default error message for wrong inputs
            print('Invalid choice, please try again!')
    except HybEncError as e:
        print(e)