import pefile
import re
from Crypto.Cipher import Blowfish
import sys

# From a real sample provided by the z2a course to identify blowfish encryption
# Sample family not provided
# sample sha256: 36684cef31a4a43473d5b12d30aabf94f56e407b0eeec14b7c1cb87efa3159b6
# Sample held its config data as a resource, in a hex string format
# The key came from a stack string of 16 bytes

def decryptFish(ciphertext, key):
    cipher = Blowfish.new(key, Blowfish.MODE_ECB)
    decrypted_data = cipher.decrypt(ciphertext)
    return decrypted_data.decode('utf-8', errors='ignore')


# Config had a null terminator
# Retrieves all resources that end with b'\x00'
def extractRsrcs(fpath):
    pe = pefile.PE(fpath)
    potential_enc_data = []
    for rsrc in pe.DIRECTORY_ENTRY_RESOURCE.entries:
        for entry in rsrc.directory.entries:
            offset = entry.directory.entries[0].data.struct.OffsetToData
            size = entry.directory.entries[0].data.struct.Size
            resource_data = pe.get_data(offset, size)

            #config appears to have a null terminator
            if resource_data[-1] == 0:
                potent_enc = (resource_data[:-1])
                potent_enc = bytes.fromhex(potent_enc.decode()) # convert from hex string, to the actual bytes
                potential_enc_data.append(potent_enc)

    return potential_enc_data

def getText(fpath):
    bfishPE = pefile.PE(fpath)
    for section in bfishPE.sections:
        if b'text' in section.Name:
            bfishText = section.get_data()
    return bfishText

# Key was a stack string of 16 btyes
# This looks for all stack strings within the valid blowfish cipher key lengths - 4, 56
def extractKeyDecData(encDataList, code):
    keyFindRegex = re.compile(rb'(\xc6(.){2}(.){1}){4,56}')
    potentialKeys = re.finditer(keyFindRegex, code)
    ipValidation = r"^((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9]).*"

    extractedConf = []

    for encData in encDataList:
        for potentialKey in potentialKeys:
            try:
                stack_str_data = potentialKey[0]
                stack_str_instruction_count = len(stack_str_data) // 4
                key = []
                for i in range(stack_str_instruction_count):
                    key.append(bytes([stack_str_data[3 + (i * 4)]])) # offset to actual immediate value in stack string
                key = b''.join(key)
                dec = decryptFish(encData, key)
                validIP = re.finditer(ipValidation, dec)
                if re.match(ipValidation, dec):
                    extractedConf.append(dec)
            except:
                pass
    return extractedConf


def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <argument>")
        sys.exit(1)
    fpath = sys.argv[1]
    potentialEncData = extractRsrcs(fpath)
    bfishText = getText(fpath)
    extractedConf = extractKeyDecData(potentialEncData, bfishText)
    for conf in extractedConf:
        print(conf)


main()