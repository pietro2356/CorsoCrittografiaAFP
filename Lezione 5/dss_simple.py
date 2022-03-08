#!/usr/bin/python3
# --Digital Signature--

# import cryptography modules
from Crypto.Signature import DSS
from Crypto.PublicKey import ECC
from Crypto.Hash import SHA3_256
from getpass import getpass
from os.path import isfile
from base64 import b64encode

# custom errors


class DSSErrorr(Exception):
    '''Error executing DSS script'''

class ReadProcessingError(DSSErrorr):
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
                raise DSSErrorr(error)

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
                raise DSSErrorr(error)



#
# VALIDATION FUNCTIONS
#


# function that validates a file's minimum length
# parameters:
# data: byte string to check
# min_len: minimum length in bytes the file must have


def check_len(data, c_len):
    if len(data) >= c_len:
        return data
    else:
        message = 'Error: the file must be at least '
        message += str(c_len) + ' bytes long.'
        raise ReadProcessingError(message)



# function that imports and validates an ECC key
# parameters:
# - data: byte string to check and import
# - private: boolean that tells if the key should be a private key


def import_key(data, private):
    passphrase = None
    if private:
        # aquire passphrase
        passphrase = getpass("Insert password to unlock the private key:")
    # import key
    try:
        key = ECC.import_key(data, passphrase=passphrase)
    except ValueError as e:
        # error message
        message = 'Error while importing the key: ' + str(e)
        if private:
            message += '\nPlease check that the password is correct.'
        raise ReadProcessingError(message)
    # check size
    if key.pointQ.size_in_bytes() < 32:
        message = 'Error: ECC size insufficient, should be at least 256 bits.'
        raise ReadProcessingError(message)
    # check type
    if private and (not key.has_private()):
        raise ReadProcessingError('Error: this is not a private key!')
    
    return key



#
# SUPPORT FUNCTIONS
#

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



# function that imports a key from file
# parameters:
# - private: boolean that tells if the key is private
# returns the imported key

def read_key(private):
    # prepare settings
    settings = {
        'error': 'Key import aborted.',
        'process': lambda data: import_key(data, private)
    }
    if private:
        settings['subject'] = 'private key'
        settings['default'] = 'ECC_sk.pem'
    else:
        settings['subject'] = 'public key'
        settings['default'] = 'ECC_pk.pem'

    key, _ = read_file(**settings)
    return key



#
# GENERATE KEYS
#


def gen_keys():
    # generate key pair
    key = ECC.generate(curve = 'secp256r1')
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
        'data': private_key.encode(),
        'subject': 'private key',
        'error': 'Output aborted.',
        'default': 'ECC_sk.pem'
    }
    out_file = write_file(**settings)
    print('Private key correctly written in "' + out_file + '"')
    # export public key
    export = {
        'format': 'PEM',
        'compress': True
    }
    public_key = key.public_key().export_key(**export)
    # save on file
    settings = {
        'data': public_key.encode(),
        'subject': 'public key',
        'default': 'ECC_pk.pem'
    }
    
    #complete export settings and write file
    name = settings['subject'].capitalize()
    settings['error'] = name + ' not saved: aborted.'
    out_file = write_file(**settings) 
    print(name + ' correctly written in "' + out_file + '"')



#
# SIGN
#


# function that computes a signature
# parameters:
# - msg: byte string to sign
# - pr_key: imported private key
# - encode: boolean that determines output type:
#   - True: b64-utf8 encoded string
#   - False: bytes (default)
# returns the signature


def get_sig(msg, pr_key, encode = False):
    #hash message
    h = SHA3_256.new(msg)
    #initialise signing
    signer = DSS.new(pr_key, 'deterministic-rfc6979')
    #sign
    sig = signer.sign(h)
    #encode and return signature
    if encode:
        sig = b64encode(sig).decode('utf-8')
    return sig



# function that signs a file


def sign():
    # read private key to use
    sk = read_key(True)

    # read file to sign, no validation
    settings = {
        'subject': 'data to sign',
        'error': 'Signing aborted.'
    }
    data, in_file = read_file(**settings)

    #sign
    signature = get_sig(data, sk)
    
    # output 
    settings = {
        'data': signature + data,
        'subject': 'signed data',
        'error': 'Output aborted.',
        'default': in_file + '.sig'
    }
    out_file = write_file(**settings)
    print('Signed data correctly written in "' + out_file + '"')



#
# VERIFY
#


# function that verifies a signature
# parameters:
# - msg: byte string to verify
# - sig: byte string containing the signature to be checked
# - pub_key: imported public key
# raises an exception if the signature does not verify
# against msg and pub_key


def ver_sig(msg, sig, pub_key):
    #hash message
    h = SHA3_256.new(msg)
    #initialise verifying
    verifier = DSS.new(pub_key, 'deterministic-rfc6979')
    #verify
    try:
        verifier.verify(h, sig)
    except ValueError:
        raise DSSErrorr('Invalid signature!')



# function that verifies a signed file


def verify():
    # read public key to use
    pk = read_key(False)

    # read signed file to verify, validating length
    sig_len = 2 * pk.pointQ.size_in_bytes()
    settings = {
        'subject': 'signed',
        'error': 'Verifying aborted.',
        'process': lambda data: check_len(data, sig_len)
    }
    data, in_file = read_file(**settings)

    # check signature
    ver_sig(data[sig_len:], data[:sig_len], pk)
    # if there are no errors the signature is valid
    prompt = 'Signature is valid!\nExport content?'
    prompt += ' (y to confirm, anything else to cancel) '
    c = input(prompt)
    if c.lower() == 'y':
        # try to deduce original filename
        if in_file[-4:] == '.sig':
            default = in_file[:-4]
        else:
            default = in_file + '.ok'
        
        export_settings = {
            'data': data[sig_len:],
            'subject': 'content data',
            'error': 'Data export aborted',
            'default': default
        }
        out_file = write_file(**export_settings)
        print('Data correctly written in "' + out_file + '"')



#
# MAIN
#


main_prompt = '''What do you want to do?
1 -> generate and save keys
2 -> sign a file
3 -> verify a signed file
0 -> quit
 -> '''
while True:
    #get user's choice and call appropriate function
    #errors are captured and printed out
    #invalid choices are ignored
    choice = input(main_prompt)
    try:
        if choice == '1':
                gen_keys()
        elif choice == '2':
                sign()
        elif choice == '3':
                verify()
        elif choice == '0':
            exit()
    except DSSErrorr as e:
            print(e)