# Per facilitare il progetto è disponibile il seguente codice
# da completare e commentare opportunamente

# importare i moduli crittografici
from Crypto.Random import get_random_bytes #per generare salt
from Crypto.Cipher import AES #per cifrare/decifrare
from Crypto.Protocol.KDF import scrypt #per generare chiave sicura
from Crypto.Hash import BLAKE2b #per hashing.
# importare una funzione di input
from getpass import getpass 
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
    key = scrypt(password=password,p=1,r=8,N=2**20,salt=salt,key_len=16) # genero chiave derivando da password (usando il salt salvato)
    cipher = AES.new(key=key,mode=AES.MODE_OCB,nonce=nonce,mac_len=16) # genero cifrario
    data = cipher.decrypt_and_verify(ciphertext=ciphertext,received_mac_tag=tag) # decifratura del file
    try:
        credentials = json.loads(data.decode('utf-8')) # da stringa json a oggetto
    except ValueError as err:
        raise IOError(str(err))
    return credentials

def save_and_exit(path, password, credentials):
    #da oggetto a stringa json
    data = json.dumps(credentials, ensure_ascii=False).encode('utf-8')
    #cifra 'data' utilizzando opportunamente la password
    salt = get_random_bytes(16) # genero salt casuale
    key = scrypt(password=password,p=1,r=8,N=2**20,salt=salt,key_len=16) # genero chiave derivando da password
    cipher = AES.new(key=key, mode=AES.MODE_OCB,mac_len=16) # genero cifrario
    ciphertext,tag = cipher.encrypt_and_digest(data) # cifratura del file
    with open(path, 'wb') as out_file:
        # salva il cifrato nel file situato in 'path'
        # (salvare anche i parametri necessari alla decifratura)
        out_file.write(salt) 
        out_file.write(cipher.nonce)
        out_file.write(tag)
        out_file.write(ciphertext)

def search_and_add(query, dic):
    if query in dic:
        #se trova l'id delle credenziali, mostrale su schermo (terminale)
        print('username: ', dic[query]['username'])
        print('password: ', dic[query]['password'])
    else:
        #se non trova, chiedi di inserire nuove credenziali con l'id passato come query
        prompt = 'Credentials not found. Add new entry?'
        prompt += '\n(y to continue, anything else to cancel)\n'
        add = input(prompt)
        if add == 'y':
            #aggiunta di nuove credenziali con variable query come id
            username_n = input('Insert username: ')
            # leggi la password in maniera opportuna
            password_n = getpass('Insert password: ')
            dic[query] = {
                    'username': username_n,
                    'password': password_n
                    }
    return dic


def log_in(username, password):
    # deriva il percorso (nome del file) del file associato all'utente
    hashedUsr = BLAKE2b.new(data = str.encode(username,'utf-8')) #hash dell'username
    path_file = hashedUsr.hexdigest() #ottieni hex leggibile dell'oggetto hash
    if os.path.exists(path_file):
        try:
            #se file esiste, ottieni le credenziali dal file
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
            #cerca le credenziali salvate con l'id query, se non trova, chiede di salvarne una con l'id inserito
            credentials = search_and_add(query, credentials)
        else:
            try:
                print('Saving data...')
                #cripta il file e lo salva
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