import pefile
from binascii import *
import re
import base64
from Crypto.Cipher import ARC4

def retrive_rdata(fpath):
    oski = pefile.PE(fpath)
    for section in oski.sections:
        if b'.rdata' in section.Name:
            oski_rdata = section.get_data()
            break
            
    return oski_rdata
def extract_rc4_key(rdata):
    matches = re.findall(rb'[0-9]{12,32}\x00', rdata)
    
    if len(matches) != 1:
        print('Unsuccessful extracting key')
        return None
        
    for m in matches:
        return (m[:-1].decode())

def get_most_called_func():
    functionCount = []
    for func in Functions():
        xref_count = 0
        for xref in XrefsTo(func):
            xref_count += 1
        functionCount.append((func, xref_count))
        
    funcs_sorted = (sorted(functionCount, key=lambda item: item[1]))
    most_called = funcs_sorted[-1:]
    return most_called[0][0]

def b64_decode_rc4_decrypt(key, enc_string):
    key_bytes = key.encode('utf-8')
    encrypted_bytes = base64.b64decode(enc_string)
    cipher = ARC4.new(key_bytes)
    decrypted_bytes = cipher.decrypt(encrypted_bytes)
    return decrypted_bytes.decode('utf-8', errors='replace')

def main():
    fpath = r"C:\Users\Kevin\Desktop\Samples\z2a challenge oski final payload\oski_final_payload.bin"
    
    rdata = retrive_rdata(fpath)
    
    rc4_key = extract_rc4_key(rdata)
    
    decrypt_strings_func_ea = get_most_called_func()
    
    enc_strings = []
    for xref in CodeRefsTo(decrypt_strings_func_ea, 0):
        arg_insn = idc.prev_head(xref)
        enc_str_ea = get_operand_value(arg_insn, 0)
        enc_str = ida_bytes.get_strlit_contents(enc_str_ea, -1, ida_nalt.STRTYPE_C, 0).decode('utf-8')
        print(b64_decode_rc4_decrypt(rc4_key, enc_str))
        
main()
