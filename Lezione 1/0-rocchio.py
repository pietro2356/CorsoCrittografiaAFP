'''
/------------------------------------------
| Copyright (c) 2022 by Rocchio Pietro 
| Lezione 1 ~ Compito
| Titolo: Encryption and decryption using the One Time Pad algorithm.
\------------------------------------------
'''

# https://docs.python.org/3/library/string.html
import string

# We generate the list of usable characters.
alphList = list(string.ascii_letters)


''' ---- Exception Manage ---- '''
## TODO: Personalizzare le eccezioni!
class SubCipherError(Exception):
    '''Error Executing Substitution Cipher Script'''


''' ---- IO Manage ---- '''
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


# Function to write file contents.
def write_file(filename, txt):
    try:
        # Open in read text mode.
        with open("Lezione 1\\ciphertext.txt", "w") as out_file:
            out_file.write(txt)
    except IOError as e:
        raise SubCipherError('Error: cannot write "cipher.txt" file: ' + str(e))
    
    print('Encrypted message correctly and saved in -> "ciphertext.txt"\n')


''' ---- Encode & Decode character ---- '''
def charToNum(char):
    ## TODO: Controllare se index corrisponde o presente.
    ## ! Lanciare eccezione in caso contrario
    return alphList.index(char)

def numToChar(num):
    return alphList[num]

def encodeChar(char, cKey):
    # cipherNum = ( charToNum(char) + charToNum(cKey) ) % 26
    # cipherText = numToChar(cipherNum)
    # return cipherText
    return numToChar((charToNum(char) + charToNum(cKey)) % len(alphList))

def decodeChar(char, cKey):
    # plainNum = charToNum(char) - charToNum(cKey)
    # plainText= numToChar(plainNum)
    # return plainText
    return numToChar(charToNum(char) - charToNum(cKey))


''' ---- OUT RESULT ---- '''
# Print out the result of the encryption.
def printResultEncription(plainTxt, key, cipherTxt):
    print("\nPlain Text:     " + plainTxt)
    print("Encrypted text: " + cipherTxt)
    print("Key:            " + key[0:len(plainTxt)] + "\n")

# Print out the result of the decription.
def printResultDecription(plainTxt, key, cipherTxt):
    print("\nEncrypted text: " + cipherTxt)
    print("Key:            " + key[0:len(plainTxt)])
    print("Plain Text:     " + plainTxt + "\n")


'''  ---- Encode & Decode message ---- '''
# Function that performs word encryption
def encrypt():    
    key = read_file('key.txt')
    word = input('Enter the word to encode: ')
    
    if len(word) > len(key):
        ## FIXME: Non usare eccezioni generiche, poco pratiche e introducono BUG. 
        raise Exception('\nError: Text longer than the encryption key. \nWord length: ' + str(len(word)) + '\nKey length: ' + str(len(key)) + '\nRetry...\n\n')
    
    cipherText = ""
    
    for i in range(0, len(word)):
        cipherText += encodeChar(word[i], key[i])
        
    write_file('cipherText.txt', cipherText)
    print('Text encrypted correctly!\n')
    return cipherText
    

# Function that performs word decryption
def decrypt():
    key = read_file('key.txt')
    cipherTxt = read_file('ciphertext.txt')
    plainTxt = ""
    
    for i in range(0, len(cipherTxt)):
        plainTxt += decodeChar(cipherTxt[i], key[i])
        
    print('Text decrypted correctly!')
    printResultDecription(plainTxt, key, cipherTxt)
    return plainTxt


''' ---- MAIN ---- '''
if __name__ == '__main__':
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
                ## TODO: Rimuovere il try catch.
                try:
                    encrypt()
                except Exception as e:
                    print(str(e))
            elif choice == '2':
                decrypt()
            elif choice == '0':
                break
            else:
                print('Invalid choice, please try again!')
                
        except SubCipherError as e:
            print(e)