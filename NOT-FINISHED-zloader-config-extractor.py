from Crypto.Cipher import ARC4
import binascii
import pefile
from pathlib import Path
import re
import sys

#Just need to clean up lots of the code

def zloaderExtract(filePath):
    zloaderPath = Path(filePath)
    if zloaderPath == None:
        print("Invalid Path")
        sys.exit()
    zloaderPE = pefile.PE(zloaderPath)
    zloaderVirtualBase = zloaderPE.OPTIONAL_HEADER.ImageBase
    for section in zloaderPE.sections:
        if b'.data' in section.Name:
            zloaderData = section.get_data()
            dataVA = section.VirtualAddress
            dataVsize = section.Misc_VirtualSize
        if b'.text' in section.Name:
            zloaderCode = section.get_data()
    zloaderCode = zloaderCode.hex()
    zloaderDataBase = dataVA + zloaderVirtualBase
    zloaderDataEnd = zloaderDataBase + dataVsize
    zloaderData = binascii.hexlify(zloaderData)
    findConfig = re.compile(r'68(.{8})68(.{8})e8.{8}83c408')
    foundInstances = findConfig.finditer(zloaderCode)
    #Calculates the virtual address range of the data section.
    potentialKeyList = []
    potentialConfigList = []
    KeyListInt = []
    ConfigListInt = []
    for match in foundInstances:
        potentialKeyList.append(binascii.unhexlify(match.group(1)))
        potentialConfigList.append(binascii.unhexlify(match.group(2)))
        #turned them back into bytes objects so I could reverse the endianess
    for address in potentialKeyList:
        KeyListInt.append(int.from_bytes(address, byteorder='little'))
    for address in potentialConfigList:
        ConfigListInt.append(int.from_bytes(address, byteorder='little'))
        #Made new lists with the int addresses of the found match objects
    PotentialConfigTuplePair = []
    for item in range(len(KeyListInt)):
        PotentialConfigTuplePair.append((KeyListInt[item], ConfigListInt[item]))
        #Organised the The match group pairs into actual pairs as a list of tuples. Makes easier to handle
    KeyVAConfigVA = []
    for pair in PotentialConfigTuplePair:
        NotInData = False
        for address in pair:
            if address not in range(zloaderDataBase, zloaderDataEnd):
                NotInData = True
        if NotInData == False:
            KeyVAConfigVA.append(pair)
    KeyRVAConfigRVA = []
    for pair in KeyVAConfigVA:
        KeyRVAConfigRVA.append((pair[0] - zloaderDataBase, (pair[1] - zloaderDataBase)))
    KeyConfig = []
    for keyRVA, configRVA in KeyRVAConfigRVA:
        try:
            config = zloaderData[configRVA * 2:keyRVA * 2]
            lookingForNullTerm = zloaderData[keyRVA * 2:]
            keyEnd = lookingForNullTerm.find(b'00')
            key = lookingForNullTerm[:keyEnd]
        except:
            continue
        KeyConfig.append([key, config]) 
        
    returnList = []
    for key, config in KeyConfig:
        try:
            cipher    = ARC4.new(binascii.unhexlify(key))
            decrypted = cipher.decrypt(binascii.unhexlify(config))
            decrypted = decrypted.decode('utf-8', errors='replace')
        except:
            continue     
        returnList.append(decrypted)
    return returnList


if __name__ == '__main__':
    filePath = input("Enter the file path\n")
    extracted = zloaderExtract(filePath)
    for item in extracted:
        print(item)