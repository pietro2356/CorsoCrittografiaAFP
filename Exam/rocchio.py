# Per facilitare il progetto Ã¨ disponibile il seguente codice
# da completare e commentare opportunamente

# importare i moduli crittografici
# Module to perform the hash.
from Crypto.Hash import BLAKE2b
# Function to generate a secure key
from Crypto.Protocol.KDF import scrypt
# Encryption/decryption algorithm
from Crypto.Cipher import AES
# importare una funzione di input
from getpass import getpass
# Function to generate salt
from Crypto.Random import get_random_bytes
import json
import os.path

def load_data(path, password):
    with open(path, 'rb') as in_file:
        # scomponi i dati letti in 4 pezzi, 3 hanno lunghezze precise
        salt = in_file.read(16)
        nonce = in_file.read(15)
        tag = in_file.read(16)
        ciphertext = in_file.read(-1)
    
    # decifra e salva il risultato in 'data'
    # We generate the key derived from the password, using the saved salt
    key = scrypt(password = password, p = 1, r = 8, N = 2**20, salt = salt, key_len = 16)
    # Generating the cipher with OCB
    cipher = AES.new(key = key, mode = AES.MODE_OCB, nonce = nonce, mac_len = 16)
    # Decrypt the file
    data = cipher.decrypt_and_verify(ciphertext = ciphertext, received_mac_tag = tag)
    try: 
        # Converting from json string to object
        credentials = json.loads(data.decode('utf-8'))
    except ValueError as err:
        raise IOError(str(err))
    return credentials


def save_and_exit(path, password, credentials):
    # Converting from object to json string
    data = json.dumps(credentials, ensure_ascii = False).encode('utf-8')
    # cifra 'data' utilizzando opportunamente la password
    # We generate a random salt
    salt = get_random_bytes(16)
    # Generate the key from the password
    key = scrypt(password = password, p = 1, r = 8, N = 2**20, salt = salt, key_len = 16)
    # Generating the cipher
    cipher = AES.new(key, AES.MODE_OCB)
    # Encrypting the file
    cipherText, tag = cipher.encrypt_and_digest(data)
    with open(path, 'wb') as out_file:
        # salva il cifrato nel file situato in 'path'
        # (salvare anche i parametri necessari alla decifratura)
        out_file.write(salt)
        out_file.write(cipher.nonce)
        out_file.write(tag)
        out_file.write(cipherText)


def search_and_add(query, dic):
    if query in dic:
        # If it finds the id of the credentials, show them on screen (terminal)
        print('username: ', dic[query]['username'])
        print('password: ', dic[query]['password'])
    else:
        # If it does not find the id, ask to enter new credentials with the id passed as a query
        prompt = 'Credentials not found. Add new entry?'
        prompt += '\n(y to continue, anything else to cancel)\n'
        add = input(prompt)
        if add == 'y':
            # Adding new credentials with variable query as id
            username_n = input('Insert username: ')
            # leggi la password in maniera opportuna
            password_n = getpass('Password: ')
            dic[query] = {
                    'username': username_n,
                    'password': password_n
                    }
    return dic


def log_in(username, password):
    # deriva il percorso del file associato all'utente
    # Hash the username
    hashedUsr = BLAKE2b.new(data = str.encode(username, 'utf-8'))
    # Generating a Human-Readable hex from the hash object
    path_file = hashedUsr.hexdigest()
    if os.path.exists(path_file):
        try:
            credentials = load_data(path_file, password)
        except ValueError as err:
            print('Autentication failed')
            return
        except IOError as err:
            print('Error loading data:')
            print(err)
            return
    else:
        prompt = 'User not found. Add as new?'
        prompt += '\n(y to continue, anything else to cancel)\n'
        sign_up = input(prompt)
        if sign_up == 'y':
            credentials = {}
        else:
            return
    prompt = 'Credentials to search:'
    prompt += '\n(leave blank and press "enter" to save and exit)\n'
    while True:
        query = input(prompt)
        if query != '':
            # Searches for saved credentials with the query id, if nothing is found, asks to save one with the entered id.
            credentials = search_and_add(query, credentials)
        else:
            try:
                print('Saving data...')
                # Encrypts the file and saves it
                save_and_exit(path_file, password, credentials)
                print('Data saved!')
            except IOError:
                print('Error while saving, new data has not been updated!')
            return

#MAIN
while True:
    print('Insert username and password to load data,')
    print('leave blank and press "enter" to exit.')
    username = input('Username: ')
    if username == '':
        print('Goodbye!')
        exit()
    else:
        # leggi la password in maniera opportuna
        password = getpass('Password: ')
        log_in(username, password)