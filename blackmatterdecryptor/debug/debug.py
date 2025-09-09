
import ctypes
import struct
from ctypes import wintypes
import binascii
import os

script_dir = os.path.dirname(os.path.realpath(__file__))
parent_dir = os.path.dirname(script_dir)  # one level up
dll_path = os.path.join(parent_dir, "decrypt.dll")
bmatter_decrypt = ctypes.WinDLL(dll_path)

decryptor = bmatter_decrypt.bmatter_decrypt
#char *enc[in, out - encrypts in place] , int32 size_in_bytes, char* key_buffer
#in the actual assembly, the keybuffer is hardcoded into the function, I modified it a bit so you could pass it in as an arguement

with open(r'C:\Users\Kevin\Desktop\Samples\Blackmatter\scripts\buffer.bin', 'rb') as file:
    buffer = file.read()

size = struct.unpack("<I", buffer[:4])[0]
#size = wintypes.DWORD(size)
enc = buffer[4:]
key = b'=\xc4O\xc0\r\xe8\x83\x1e'

#input("Attach debugger!")

decryptor(enc, size, key)

print(binascii.hexlify(enc))