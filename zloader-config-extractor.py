from Crypto.Cipher import ARC4
import pefile
from pathlib import Path
import re
import sys

# Zloader stores its config data as RC4 encrypted data, with the key appended onto the encrypted data
# It pushes the pointer to the config data, as well as the pointer to the key to a decryption function
# This script looks for a fucntion signature of two arguements being pushed, followed by call
# Checks if these arguements are addresses within the data section
# Then attempts to use their values to decrypt the config


def get_data_text(zloaderPath):
    zloaderPE = pefile.PE(zloaderPath)
    global ImageBase
    ImageBase = zloaderPE.OPTIONAL_HEADER.ImageBase
    for section in zloaderPE.sections:
        if b'.data' in section.Name:
            global zloaderData
            zloaderData = section.get_data()
            global dataVA
            dataVA = section.VirtualAddress
            global dataVsize
            dataVsize = section.Misc_VirtualSize
            global zloaderDataBase
            zloaderDataBase = dataVA + ImageBase
            global zloaderDataEnd
            zloaderDataEnd = zloaderDataBase + dataVsize
        if b'.text' in section.Name:
            zloaderCode = section.get_data()
    return zloaderData, zloaderCode


def extract_potential_keys_conf(zloaderData, zloaderCode):
    # looking for functions in which 2 args are pushed to it.
    findConfig = re.compile(rb'\x68(.{4})\x68(.{4})\xe8.{4}\x83\xc4\x08')
    foundInstances = findConfig.finditer(zloaderCode)

    #Calculates the virtual address range of the data section.
    keyConfAddrs = []

    KEY = 1
    CONFIG = 2
    for match in foundInstances:
        keyConf = []
        keyConf.append(int.from_bytes((match.group(KEY)), byteorder='little'))
        keyConf.append(int.from_bytes((match.group(CONFIG)), byteorder='little'))
        keyConfAddrs.append(keyConf)


    # checks if the arguements from this function are addresses within the data section
    validKeyAndConfigAddrs = []
    for addrs in keyConfAddrs:
        if all([addr in range(zloaderDataBase, zloaderDataEnd) for addr in addrs]):
            validKeyAndConfigAddrs.append(addrs)
    return validKeyAndConfigAddrs


def decrypt_conf(fpath, keyConfAddrs):
    zloaderPE = pefile.PE(fpath)
    keyConfig = []
    for keyRVA, configRVA in keyConfAddrs:
        confLen = keyRVA - configRVA
        try:
            config = zloaderPE.get_data(configRVA - ImageBase, confLen)
            keyDataExtra = zloaderPE.get_data(keyRVA - ImageBase, 100)
            keyEnd = keyDataExtra.find(b'\x00')
            key = keyDataExtra[:keyEnd]
        except:
            continue
        keyConfig.append([key, config]) 

    decrypted_config = []
    for key, config in keyConfig:
        try:
            cipher    = ARC4.new(key)
            decrypted = cipher.decrypt(config)
            #decrypted = decrypted.decode('utf-8', errors='replace')
            findURLS = re.compile(rb'http[^\x00]*')
            urls = findURLS.finditer(decrypted)
            for match in urls:
                decrypted_config.append(match[0])
        except:
            continue     
    return decrypted_config



def main():
    if len(sys.argv) < 2:
        print("Usage: python script.py <file_path>")
        sys.exit(1)
    filePath = sys.argv[1]
    data, text = get_data_text(filePath)
    keyConfAddrs = extract_potential_keys_conf(data, text)
    extracted = decrypt_conf(filePath, keyConfAddrs)
    for item in extracted:
        print(item)

main()