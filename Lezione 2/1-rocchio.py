'''
/------------------------------------------
| Copyright (c) 2022 by Rocchio Pietro 
| Lezione 2 ~ Compito
| Titolo: Cifratura e Decifratura Simmetrica
|------------------------------------------
| COSA DEE FARE IL PROGRAMMA:
|   - TODO: Specificando se vuole cifrare o decifrare.
|   - TODO: Specificare da input il percorso del file da cifrare/decifrare.
|       - TODO:  Path file dove salvare il risultato dell'operazione.
|   - TODO:  Includere o meno l'autenticazione dei dati cifrati.
|   - TODO: Usare cifrari ed OM adeguati alla scelta (usate 2 cifrari diversi).
|   - TODO: Cifratura la chiave va creata in maniera appropriata e poi salvata in chiaro in un file (il cui nome viene inserito dall'utente).
|   - TODO: Lo stesso file verrà letto in fase di decifratura (sempre chiedendo all'utente quale file usare).
|   - TODO: Permettere più operazioni, finché l'utente non decide di uscire.
|   - TODO: Gestire correttamente tutte le eccezioni che possono essere lanciate dai vari metodi.
|   - TODO: Seguire pratiche crittografiche corrette, essere il più chiaro possibile (commentate a dovere).
\------------------------------------------
'''

# IMPORT LIBRERIE
#importing the os module
import os
import sys
import tkinter as tk
from tkinter.filedialog import askopenfilename
from tkinter.filedialog import asksaveasfilename
tk.Tk().withdraw()

import Crypto.Random as rnd
from Crypto.Cipher import Salsa20



''' ---- Exception Manage ----'''
class CypherException(Exception):
    pass

class MainException(Exception):
    pass

class SelectionErrorException(Exception):
    pass


''' ---- File Path Selection ----'''
# fn = askopenfilename(initialdir=os.getcwd())
# print(fn)


''' ---- IO Manage ----'''
# Write a file
def write_file(file_path, txt):
    try:
        # Open in read text mode.
        with open(file_path, "bw") as out_file:
            out_file.write(txt)
    except IOError as e:
        raise CypherException('Error: cannot write ' + file_path +' file: ' + str(e))
    
    print('Encrypted message correctly and saved in -> ' + file_path +'\n')

# Read a file
def read_file(prompt, validate=None):# se validazione non c'è non accade nulla
    while True:
        # path = input(prompt)
        path = prompt
        # path = askopenfilename(initialdir=os.getcwd(), title='Select file to encrypt')

        try:
            with open(path, 'rb') as in_file:
                content = in_file.read()
            
            if validate == None:
                return content

            val_err = validate(content)
            if val_err == '':
                return content
            print(val_err)

        except IOError as e:
            print('Errord: Cannot read file '+ path + ': '+ str(e))

        choice = input ('(q to abort, anything else to try again) ')
        if choice == 'q':
            raise CypherException('Input aborted')
        
        
# Check length of the data
def check_c_len(data, c_len): 
        if(len(data)) >= c_len:
            return ""
        else: 
            return "Error: Ciphertext must be at least " + str(c_len) + " bytes long."


# c_data = read_file('Enter Ciphertext file: ', lambda data: check_c_len(data, 31))

'''  ---- auth ---- '''
def encryptWithAuth(bin_data):
    pass

def encryptWithOUTAuth(bin_data):
    key = rnd.get_random_bytes(16)
    write_file(askopenfilename(initialdir=os.getcwd(), title='Write key file'), key)
    
    cipher = Salsa20.new(key)
    return cipher.nonce + cipher.encrypt(bin_data)



def decryptWithAuth(key_file, ciphertext_file):
    pass


def decryptWithOUTAuth(key_file, ciphertext_file):
    nonce = ciphertext_file[:8]
    cipherTxt = ciphertext_file[8:]
    
    cipher = Salsa20.new(key_file, nonce)
    return cipher.decrypt(cipherTxt)



'''  ---- Encode & Decode message ---- '''
def encrypt():    
    # load file
    print("Select file to encrypt: ")
    in_file_path = askopenfilename(initialdir=os.getcwd(), title='Select file to encrypt')
    print("Choose where to save your file: ")
    out_file_path = asksaveasfilename(initialdir=os.getcwd(), title='Choose where to save your file')
    
    print("I am reading the file...")
    check_bin_data = read_file(in_file_path, lambda data: check_c_len(data, 31))
    
    
    choice = input("Do you want to encrypt with authentication (y/N): ").upper()
    
    if choice == 'Y':
        cipherTXT = encryptWithAuth(check_bin_data)
        write_file(out_file_path, cipherTXT)
    elif choice == 'N':
        cipherTXT = encryptWithOUTAuth(check_bin_data)
        write_file(out_file_path, cipherTXT)
    else:
        raise SelectionErrorException('Invalid choice, please try again!')
    # TODO: Convert file to bin
    # TODO: Chose if user want auth or not
    # If he want auth use AEX, GCM, ETC...
    # Else use salsa20, etc... 
    
    # TODO: for every encryption generate a corresponding key.
    # TODO: Save encrypted file and key into local directory. 
    
    

def decrypt():
    # key = 
    # file = read_file(askopenfilename(initialdir=os.getcwd(), title='Select key file'), lambda data: check_c_len(data, 31))


# load file
    print("Select file to decrypt: ")
    in_file_path = askopenfilename(initialdir=os.getcwd(), title='Select file to decrypt')
    
    print("Select file key: ")
    in_key_file_path = askopenfilename(initialdir=os.getcwd(), title='Select key file')
    
    
    print("Choose where to save your decripted file: ")
    out_plain_file_path = asksaveasfilename(initialdir=os.getcwd(), title='Choose where to save your file')
    
    print("I am reading the file...")
    check_bin_data = read_file(in_file_path, lambda data: check_c_len(data, 31))
    
    
    choice = input("Do you want to encrypt with authentication (y/N): ").upper()
    
    if choice == 'Y':
        cipherTXT = decryptWithAuth(check_bin_data)
        write_file(out_plain_file_path, cipherTXT)
    elif choice == 'N':
        cipherTXT = decryptWithOUTAuth(read_file(in_key_file_path), read_file(in_file_path))
        write_file(out_plain_file_path, cipherTXT)
    else:
        raise SelectionErrorException('Invalid choice, please try again!')



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
                encrypt()
            elif choice == '2':
                decrypt()
            elif choice == '0':
                break
            else:
                print('Invalid choice, please try again!')
                
        except MainException as e:
            print(e)

    