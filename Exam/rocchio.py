# Per facilitare il progetto Ã¨ disponibile il seguente codice
# da completare e commentare opportunamente

# importare i moduli crittografici
from hashlib import blake2b
from hashlib import scrypt
from Crypto.Cipher import AES
# from # import #
# importare una funzione di input
# from # import #
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
    key = scrypt(password = password, p = 1, r = 8, N = 2**20, salt = salt, key_len = 16)
    cipher = AES.new(key = key, mode = AES.MODE_CBC, nonce = nonce, mac_len = 16)
    data = cipher.decrypt_and_verify(ciphertext = ciphertext, received_mac_tag = tag)
    try: 
        credentials = json.loads(data.decode('utf-8'))
    except ValueError as err:
        raise IOError(str(err))
    return credentials


def save_and_exit(path, password, credentials):
    data = json.dumps(credentials, ensure_ascii=False).encode('utf-8')
    #cifra 'data' utilizzando opportunamente la password
    # # = #
    # key = #
    # cipher = #
    # # = #
    with open(path, 'wb') as out_file:
        # salva il cifrato nel file situato in 'path'
        # (salvare anche i parametri necessari alla decifratura)
        # out_file.write(#)
        # out_file.write(#)
        # out_file.write(#)
        # out_file.write(#)


def search_and_add(query, dic):
    if query in dic:
        print('username: ', dic[query]['username'])
        print('password: ', dic[query]['password'])
    else:
        prompt = 'Credentials not found. Add new entry?'
        prompt += '\n(y to continue, anything else to cancel)\n'
        add = input(prompt)
        if add == 'y':
            username_n = input('Insert username: ')
            # leggi la password in maniera opportuna
            password_n = #
            dic[query] = {
                    'username': username_n,
                    'password': password_n
                    }
    return dic


def log_in(username, password):
    # deriva il percorso del file associato all'utente
    hashedUsr = blake2b.new(data = str.encode(username, 'utf-8'))
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
            credentials = search_and_add(query, credentials)
        else:
            try:
                print('Saving data...')
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
        password = #
        log_in(username, password)