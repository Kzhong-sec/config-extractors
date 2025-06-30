
import pefile
from pathlib import Path
import re
from Crypto.Cipher import Blowfish
def decryptFish(ciphertext, key):
    cipher = Blowfish.new(key, Blowfish.MODE_ECB)
    decrypted_data = cipher.decrypt(ciphertext)
    print(decrypted_data.decode('utf-8', errors='ignore'), '\n\n')
bfishPathobj = Path(r"C:\Users\Kevin\Desktop\bfish\sendsafe.bin")
bfishPE = pefile.PE(bfishPathobj)
for section in bfishPE.sections:
    if b'text' in section.Name:
        bfishText = section.get_data()

bfishText = bfishText.hex()
findKeyRe = re.compile(r'(c6(.){4}(.){2}){16}')

foundKey = re.finditer(findKeyRe, bfishText)
encryptedData = 'BF8744B38F94407E911C665FEAF0F1F19E9193619F2AA79237763BE84CFBBE19CE6F6CDCCFEE25674679360757EC09ED3CFC1BD044BDA625'
encryptedData = bytes.fromhex(encryptedData)
for matchObj in foundKey:
    instructionsStart = matchObj.start()
    key = []
    for keyChar in range(16):
        key.append(bfishText[instructionsStart + 6:instructionsStart + 8])
        instructionsStart += 8
    key = ''.join(key)
    print(key)
    decryptFish(encryptedData, bytes.fromhex(key))

#Extracted a key made through a stack string of 16 bytes.
#However successfully extract the resources to brute force them with the key. Just raw copy pasted it unfortunately
#resource here just meaning, actual PE resource from .rsrc. Just had pefile issues.
#Also this was a sample showing blowfish cipher from z2a. The family is not literally called blowfish