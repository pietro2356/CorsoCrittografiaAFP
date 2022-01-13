'''
/------------------------------------------
| Copyright (c) 2022 by Rocchio Pietro 
| Lezione 1 ~ Compito
| Titolo: Encryption and decryption using the One Time Pad algorithm.
\------------------------------------------
'''

# FUNCTION: 
#   - Encode
#   - Decode
#   - Exit

# NOTE: 
# CHAR to ASCII
# ord('h') -> 104

# ASCII to CHAR
# chr(104) -> 'h'


# https://docs.python.org/3/library/string.html
import string


# We generate the list of usable characters.
alphList = list(string.ascii_lowercase)


# ---- Exception Manage ----
class SubCipherError(Exception):
    '''Error Executing Substitution Cipher Script'''


# ---- IO Manage ----
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


# function 
def write_file(filename, txt):
    try:
        # Open in read text mode.
        with open("Lezione 1\\ciphertext.txt", "w") as out_file:
            out_file.write(txt)
    except IOError as e:
        raise SubCipherError('Error: cannot write "cipher.txt" file: ' + str(e))
    
    print('Encrypted message correctly and saved in -> "ciphertext.txt"\n')


# ---- Encode & Decode character ----
def charToNum(char):
    return alphList.index(char)

def numToChar(num):
    return alphList[num]

def encodeChar(char, cKey):
    # cipherNum = ( charToNum(char) + charToNum(cKey) ) % 26
    # cipherText = numToChar(cipherNum)
    # return cipherText
    return numToChar((charToNum(char) + charToNum(cKey)) % 26)

def decodeChar(char, cKey):
    # plainNum = charToNum(char) - charToNum(cKey)
    # plainText= numToChar(plainNum)
    # return plainText
    return numToChar(charToNum(char) - charToNum(cKey))


# ---- Encode & Decode character ----
def printResult(plainTxt, key, cipherTxt):
    print("\nPlain Text:     " + plainTxt)
    print("Key:            " + key[0:len(plainTxt)])
    print("Encrypted text: " + cipherTxt + "\n")


# ---- Encode & Decode message ----
def encrypt():    
    # TODO: Check the length of word!
    key = read_file('key.txt')
    word = input('Enter the word to encode: ')
    
    if len(word) > len(key):
        raise Exception('\nError: Text longer than the encryption key. \nWord length: ' + str(len(word)) + '\nKey length: ' + str(len(key)) + '\nRetry...\n\n')
    
    cipherText = ""
    
    
    for i in range(0, len(word)):
        cipherText += encodeChar(word[i], key[i])
        
    write_file('cipherText.txt', cipherText)
    print('Text encrypted correctly!\n')
    return cipherText
    

def decrypt():
    key = read_file('key.txt')
    cipherTxt = read_file('ciphertext.txt')
    plainTxt = ""
    
    for i in range(0, len(cipherTxt)):
        plainTxt += decodeChar(cipherTxt[i], key[i])
        
    print('Text decrypted correctly!')
    printResult(plainTxt, key, cipherTxt)
    return plainTxt


# ---- MAIN ----
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