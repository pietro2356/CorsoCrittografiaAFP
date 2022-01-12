#------------------------------------------
# Copyright (c) 2022 by Rocchio Pietro 
# Lezione 1
# Caesar's cipher similar
#------------------------------------------

alph =   'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZZ!£$%&/()=?^ì,.;:-_1234567890  '
# alph = 'abcdefghijklmnopqrstuvwxyz'
# key =    'q,weF68.bnow indaafwe2345gwer!qfvn$&2dRTGAEGQE3ty&/u3$WHTQAEW3r"qFgeaHJEHAG A WER '

msg = 'ciao'


# Exception definitions
class SubCipherError(Exception):
    '''Error Executing Substitution Cipher Script'''

def substitute(in_str, key_1, key_2):
    # Input controller
    if len(key_1) != len(key_2):
        raise SubCipherError('Error: key and alphabet should be the same length\n- Key len -> ' + str(len(key_1)) + '\n- Alph len -> ' + str(len(key_2)))
        
    # initialize out string
    out_str = ''

    # Scorriamo la stringa
    for char in in_str:
        # find position in reference alphabet.
        index = key_1.find(char)
        
        if index < 0:
            # raise <=> Throw new Exception
            raise SubCipherError('Error: Message contains invalid character: "' + char + '"')
        
        # Append to out the corresponding character in the permuted alphabet.
        out_str += key_2[index]
    
    return out_str


# Function to read file contents.
def read_file(filename):
    # Manage IO Exception.
    try:
        # Open in read text mode.
        with open("Lezione 1\\" + filename, 'r') as in_file:
            read_str = in_file.read()
    except IOError as e:
        raise SubCipherError('Error: cannot read ' + filename + ' file: ' + str(e))
    
    return read_str.strip('\n')


# Function that perform encrypt
def encrypt(in_key_file):
    key = read_file(in_key_file)
    msg = input('Type message to encrypt:\n')
    cipherTxt = substitute(msg, alph, key)
    
    try:
        # Open in read text mode.
        with open("Lezione 1\\cipher.txt", "w") as out_file:
            out_file.write(cipherTxt)
    except IOError as e:
        raise SubCipherError('Error: cannot write "cipher.txt" file: ' + str(e))
    
    print('Encrypted message correctly and saved in -> "cipher.txt"\n')



# Function that perform decrypt
def decrypt(in_cipher_file, in_key_file):
    key = read_file(in_key_file)
    cipherTxt = read_file(in_cipher_file)
    plainTxt = substitute(cipherTxt, alph, key)
    
    print('\nThe decripter message is: ' + plainTxt + '\n')
    


# ---- MAIN -----
while True:
    prompt = '''What do you want to do?
    1 -> Encrypt message.
    2 -> Decrypt message.
    
    0 -> Exit.
--> '''

    # Get user input from prompt and call the corresponding function.
    # Errors are captured and printed to stdout.
    choice = input(prompt)
    try:
        if choice == '1':
            encrypt('key.txt')
        elif choice == '2':
            decrypt('cipher.txt', 'key.txt')
        elif choice == '0':
            break
        else:
            print('Invalid choice, please try again!')
            
    except SubCipherError as e:
        print(e)