''''Siori grazie a @Jpmand311 e @IvanoSilvestri  che hanno craccato l'esercizio del prof, ecco a voi il riassunto delle parti importanti                                                                                Per crittografia

Da usare cipher Blacke2b per hashare gli usaername --> Nome dell'username del prof = username
 
 
Da inserire come dato username : "username"
Da inserire come password : "password"

Script requirements:
Use Blake2b per username hash:'''

from hashlib import blake2b, scrypt
import json
from Crypto.Cipher import AES


def log_in(username, password):
    # deriva il percorso del file associato all'utente
    hashedUsr = blake2b.new(data=str.encode(username,'utf-8'))
    path_file = hashedUsr.hexdigest()
 
 
'''Use AES (mode OCB) per criptare e decriptare 

( ordine del salvataggio/lettura del file è salt(16) + nonce(15) + tag(16) + ciphertext(...) ):''''

def load_data(path, password):
    with open(path, 'rb') as in_file:
        # scomponi i dati letti in 4 pezzi, 3 hanno lunghezze precise 
        salt = in_file.read(16) 
        nonce = in_file.read(15)  
        tag = in_file.read(16) 
        ciphertext = in_file.read(-1)  
    
    # decifra e salva il risultato in 'data'
    key = scrypt(password=password,p=1,r=8,N=2**20,salt=salt,key_len=16)  
    cipher = AES.new(key=key,mode=AES.MODE_OCB,nonce=nonce,mac_len=16)  
    data = cipher.decrypt_and_verify(ciphertext=ciphertext,received_mac_tag=tag)  
    try: 
        credentials = json.loads(data.decode('utf-8'))