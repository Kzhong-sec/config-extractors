import pefile
from Crypto.Cipher import ARC4
import sys


def main():
    if len(sys.argv) < 2:
        print("Usage: python script.py <file_path>")
        sys.exit(1)
    fpath = sys.argv[1]
    pe = pefile.PE(fpath)
    for rsrc in pe.DIRECTORY_ENTRY_RESOURCE.entries:
        for entry in rsrc.directory.entries:
            offset = entry.directory.entries[0].data.struct.OffsetToData
            size = entry.directory.entries[0].data.struct.Size
            
            resource_data = pe.get_data(offset, size)

            enc_executable = resource_data[28:]
            key = resource_data[12:27]
            cipher = ARC4.new(key)
            decPayload = cipher.decrypt(enc_executable)
            print(decPayload[:2])
            with open("DecryptedPayload.bin", "wb") as payload:
                payload.write(decPayload)

main()
