#1-silvestri-py
#Author: Ivano Silvestri
#2022

import os

#user the 
from Crypto.Cipher import AES #for simmetric cypher with autentication
from Crypto.Cipher import Salsa20 #for simmetric cypher without autentication
from Crypto.Random import get_random_bytes #for generating random key


#get current directory
curDirectory = os.getcwd()

#Exeption on find position in text
class SimCipherError(Exception):
    '''Error executing Simmetric Cipher Script'''


#read a text file and return the content
def read_txt_file(name):

    try:
        with open(name, 'r') as in_file:
            read_str = in_file.read()
    except IOError as e:
        raise SimCipherError('Error: cannot read '+ name + ' file: ' + str(e))
    #delete possible trailing newlines and return
    return read_str.strip('\n')


#write the encripted message in file
def writeOnFile(file,encrMessage):

    try:
        with open(file, 'wb') as out_file:
            out_file.write(encrMessage)
    except IOError as e:
        raise SimCipherError('Error: cannot write file: '+ file +' - '+ str(e))

    #print a message where the data was written
    print('\nData correctly saved in '+file+':\n')

#read the keyfile
def readKey(key):

    try:
        with open(key + '.txt', 'rb') as in_file:
            read_key = in_file.read()
    except IOError as e:
        raise SimCipherError('Error: cannot read '+ key+ ' file: ' + str(e))

    #delete possible trailing newlines and return
    return read_key#.strip('\n')

#----------------------------------------------------
#read encrypted file
def read_file(prompt, validate=None):#se validazione non c'è non accade nulla
    while True:
        #path = input(prompt)
        path = prompt

        try:
            #il blocco with as chiuderà il file 
            with open(path, 'rb') as in_file: #lettura in binario
                content = in_file.read()
            
            if validate == None:
                return content

            val_err = validate(content)
            if val_err == '':
                return content
            print(val_err)

        except IOError as e:
            print('Errord: cannot read file '+ path + ': '+ str(e))

        choice = input ('(q to abort, anything else to try again) ')
        if choice == 'q':
            raise SimCipherError('Input aborted')

#controllare che il file input abbia lunghezza sufficiente tag + della nonce 

def check_c_len(data, c_len):
    if len(data) >= c_len:
        return ''
    return 'Error: the cyphertext must be at least ' + c_len + ' bytes long.'

    #c_data = read_file ('Documenti/cipher_msg.txt', lambda data: check_c_len(data,31))#verificare la lunghezza di 
    return c_data

#----------------------------------------------------


#encryption using Salsa20 (without autentication)
def cypherNoAutentication(msgText, usrFile, usrDir, usrKey):
    print('You choose a cypher alghorithm without autentication!\n')

    plaintext = msgText
    usrFileName = usrFile+'_NAUT.bin'
    usrDirName = usrDir
    usrKeyName = usrKey+'_NAUT.txt'
    
    
    
    key = get_random_bytes(32)
    cipher = Salsa20.new(key)
  
    writeOnFile(usrDirName+'/'+usrKeyName,key)
    #writeOnFile('Documenti/Salsa20_cipher_key.txt',key)
   
    msg = cipher.nonce + cipher.encrypt(plaintext)
    
    writeOnFile(usrDirName+'/'+usrFileName,msg)    


#decryption using Salsa20 (without autentication)

def decryptNoAutentication():
    print('Message with no autentication!\n')

    secret = readKey('Documenti/cipher_key')

    cyph_text = read_file('Documenti/cipher_msg.txt')
    msg_nonce = cyph_text [:8]
    ciphertext = cyph_text [8:]
    cipher = Salsa20.new(key=secret, nonce=msg_nonce)
    plaintext = cipher.decrypt(ciphertext)
    print(plaintext.decode("utf-8"))
    

#encryption using Encrypt-then-Authenticate-then-Translate(EAX) (with autentication AES)

def encryptEAX (msgText, usrFile, usrDir, usrKey):
    print('crittografia con OM EAX\n')
    
    data = msgText
    key = get_random_bytes(16)
    usrFileName = usrFile+'_AES.bin'
    usrDirName = usrDir
    usrKeyName = usrKey+'.txt'
    
    #writes the key on file
                 
    writeOnFile(usrDirName+'/'+usrKeyName,key)

   
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(data)

    file_out = open(usrDirName+'/'+usrFileName, 'wb')
    [ file_out.write(x) for x in (cipher.nonce, tag, ciphertext) ]
    file_out.close()


#decryption using Encrypt-then-Authenticate-then-Translate(EAX) (with autentication AES)
def decryptEAX ():
    print('decrittografia con OM EAX')
    file_in = open('14_55_AES.bin', 'rb')
    nonce, tag, ciphertext = [ file_in.read(x) for x in (16, 16, -1) ]

    key = readKey('14_55_key')
    cipher = AES.new(key, AES.MODE_EAX, nonce)
    data = cipher.decrypt_and_verify(ciphertext, tag)
    print('messaggio originale: '+data.decode("utf-8"))




def encrypt():

    print('hai scelto di criptare\n')
    usrFileName = ''
    usrDirName = ''
    usrKeyName = ''


    #let user to choose the directory where to store the encrypted file

    while True:

        try:
            usrDirName = input('The current directory is '+curDirectory +
            '\nPress enter to store the crypted files into the current direcory or insert the directory name:\n')
            
            print("scelta utente = "+usrDirName)

            if usrDirName != '' and os.path.isdir(usrDirName) == False:
                print('The direcory\"'+ usrDirName +'\" doesn\'t exist! Please insert an existing Directory!\n')
                
            
            elif usrDirName == '':
                               
                usrDirName = curDirectory
                print('Data will be stored in: '+ usrDirName+'\n')
                break
                
            
            else:
                
                usrDirName = usrDirName +'/'
                print('Data will be stored in: '+ usrDirName+'\n')
                break

        except SimCipherError as e:
            print(e)

    
    #ask user to choose the filename where to store the encrypted file

    while True:

        try:
            usrFileName = input('Please insert the filename for crypted file:\n(Filename)')

            if usrFileName == '':
                print('The filename cannot be empty, please insert a valid  name')
            
            else:
                break
                
        except SimCipherError as e:
            print(e)

    #ask user to choose the key filename where to store the encrypted file
    while True:

        try:
            suggestKeyName = input('The keyfile will be created as '+usrFileName+'_key.txt\n'+
                                'Would you like to change the key filename? Y(yes) N(no)')

            #if user accept proposed filename as key filename
            if suggestKeyName== 'Y' or suggestKeyName == 'y':
                usrKeyName = input('\nPlease insert the key filename: ')
                break
                
            
            #if user accept proposed filename as key filename
            elif suggestKeyName == 'N' or suggestKeyName== 'n':                
                usrKeyName = usrFileName+'_key'
                break
            
            else:
                print('\nInvalid choice! Please type Y or N')
        
        except SimCipherError as e:
            print(e)

    
                                
    #ask user if autentication is required
    while True:
                
        usr_choice_aut = input('''Is authentication required? Y(yes) N(no) Q(quit) : ''')

        try:
            if usr_choice_aut == 'Y' or usr_choice_aut =='y':
                print('utente ha scelto l\'autenticazione -> '+usr_choice_aut)
                
                usr_data = input('nome file da crittografare -> \n')
                usr_msg = read_txt_file(usr_data)
                encryptEAX(bytes(usr_msg, 'utf-8'),usrFileName,usrDirName,usrKeyName)
                break


            elif usr_choice_aut == 'N' or usr_choice_aut =='n':
                print('utente ha scelto di non autenticare -> '+usr_choice_aut)
                usr_data = input('nome file da crittografare -> \n')
                usr_msg = read_txt_file(usr_data)               
                cypherNoAutentication(bytes(usr_msg, 'utf-8'),usrFileName,usrDirName,usrKeyName)
                break
                
                break

            elif usr_choice_aut == 'Q' or usr_choice_aut =='q':
                print('utente ha scelto di tornare indietro -> '+usr_choice_aut)
                encrypt()                      
            
            
            else:
                print('Please insert Y or N or Q to go back')
        except SimCipherError as e:
            print(e)



def decrypt():

    print('hai scelto di decriptare\n')
    usrFileName = ''
    usrDirName = ''
    usrKeyName = ''
    
    #user choose the directory
    
    #user choose the file to decrytp
    
    #user choose the key to decript
    
    
    while True:

        usr_choice = input('''Would yuou like to use Autentication? Y (yes) N (no):  ''')

        try:

            if usr_choice == 'Y' or usr_choice == 'y':

                decryptEAX ()

            elif usr_choice == 'N' or usr_choice == 'n':
                decryptNoAutentication()
                break

        except SimCipherError as e:
            print(e)
        
    
    
#MAIN
while True:
    prompt = ''' What do you want to do?
    1 = encrypt
    2 = decrypt
    0 = quit
-> '''

    #get user's choice and call appropriate function
    #errors are captured and printed out
    choice = input(prompt)
    try:
        if choice == '1':
            encrypt()
        elif choice == '2':
            decrypt()
        elif choice == '0':
            
            print ('grazie arrivederci!\n')
            exit()
        else:
            print('Invalid choice please try again!')
    except SimCipherError as e:
        print(e)
