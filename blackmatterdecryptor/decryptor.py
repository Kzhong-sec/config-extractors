
import ctypes
import struct
import os
import base64

import pefile
from . import aplib

class BlackMatterDecryptor():
    """
    Decryptor and parser for BlackMatter ransomware samples.

    Usage:

    1. Automatic key & config extraction:
       - The first 8 bytes of the pdata section are used as the key.
       - The bytes following that are used as the config data.
       - Simply call `decrypt_config()` then `extract_all()` after creating an instance.

    2. Manual key & config supply:
       - Pass `key` and `config_va` in the constructor if the config is stored differently.
       - Then call `decrypt_config()`.

    3. Accessing only the custom decryptor:
       - Pass in a key value set the `config_va` argument to 0, to use `cust_decrypt_wrapper()` or `cust_decrypt()` directly.
       - You can also attempt to extract the key and config VA via `extract_from_section_at()`.
    """
    def __init__(self, sampleFpathAbsolute: str, key:bytes = None, config_va: int =None):
        self.pe = pefile.PE(sampleFpathAbsolute)

        self.data = self.pe.__data__
        
        try:
            self.key = key if key is not None else self.extract_key()
        except LookupError:
            self.key = None
            print("Warning: Could not automatically extract the key.\nPlease provide it manually to use decryption functions.\nOther functionality is still available.")

        if config_va is None:
            self.config_va = self.get_segment_va(b'.pdata') + 12
        else:
            self.config_va = config_va

        self.decrypted_main_config = None
        self.b64_decoded = None
        self.conflig_flags = None

        #char *enc[in, out - encrypts in place] , int32 size_in_bytes, char* key_buffer
        #in the actual assembly, the keybuffer is hardcoded into the function, I modified it a bit so you could pass it in as an argument
        script_dir = os.path.dirname(os.path.realpath(__file__))
        dll_path = os.path.join(script_dir, "decrypt.dll")
        bmatter_decrypt = ctypes.WinDLL(dll_path)
        self.decryptor = bmatter_decrypt.bmatter_decrypt

    def extract_key(self, segment_name_with_config: bytes = b'.pdata'):
        va = self.get_segment_va(segment_name_with_config)
        return self.get_bytes_at(va, 8)

    def get_bytes_at(self, va: int, size: int):
        rva = va - self.pe.OPTIONAL_HEADER.ImageBase
        file_offset = self.pe.get_offset_from_rva(rva)
    
        return self.data[file_offset:file_offset + size]

    def cust_decrypt(self, enc_buffer: bytes, size: int):
        self.decryptor(enc_buffer, size, self.key)
        decrypted = enc_buffer

        return decrypted
    
    def extract_from_section_at(self, segment_name: bytes):
        self.config_va = self.get_segment_va(segment_name) + 12
        self.key = self.extract_key(self, segment_name)

    def get_segment_va(self, name: bytes):
        va = None

        for section in self.pe.sections:
            if section.Name.strip(b'\x00') == name:
                va = self.pe.OPTIONAL_HEADER.ImageBase + section.VirtualAddress
                break
        if va:
            return va
        else:
            error_message = f"{name} segment not found in the PE file"
            for section in self.pe.sections:
                if name in section.Name.strip(b'\x00'):
                    error_message += f"\nDid you mean {section.Name.strip(b'\x00')}?"
            raise LookupError(error_message)
        
    def cust_decrypt_wrapper(self, address_of_encrypted: int):
        """
        This is for when the sample uses the wrapper function for its custom decryptor. It passes the encrypted buffer as an offset, and the prior dword is the size.
        The adress should be the encrypted buffer address, not the address where the size is stored, as that is how it's called within the sample
        """
        size = struct.unpack("<I", self.get_bytes_at(address_of_encrypted - 4, 4))[0]
        enc_buffer = self.get_bytes_at(address_of_encrypted, size)
        return self.cust_decrypt(enc_buffer, size)

    def decrypt_config(self):
        """
        The sample I was analyzing stored it's config in a segment called b'.pdata', with specific offsets for the keys, sizes and config data. Will need to adjust the default args if it does not do this.
        """
        if not self.config_va:
            print("Must apply the config_va attribute!")
            return
        self.decrypted_main_config = aplib.aplib_decompress(self.cust_decrypt_wrapper(self.config_va))
        return self.decrypted_main_config
    
    def extract_public_rsa(self):
        if not self.config_va:
            print("Must apply the config_va attribute!")
            return
        self.rsa = {"RSA Public" : self.decrypted_main_config[:128].hex()}
        return self.rsa


    def extract_config_flags(self) -> dict:
        if self.decrypted_main_config is None:
            print("Configuration must be decrypted first")
            return None
        #config_flags_offset = 160
        config_flags = {
            'unk1' : self.decrypted_main_config[160],
            'Replace with random file name' : self.decrypted_main_config[161],
            'Find Domain Admins' : self.decrypted_main_config[162],
            'Skip hidden files' : self.decrypted_main_config[163],
            'Check for Russian Keyboard Layout' : self.decrypted_main_config[164],
            'Encrypt local files' : self.decrypted_main_config[165],
            'Encrypt network shares' : self.decrypted_main_config[166],
            'Kill processes within config process hashes' : self.decrypted_main_config[167],
            'Kill services within config services hashes' : self.decrypted_main_config[168],
            'Load worker executable for secure self erase' : self.decrypted_main_config[169],
            'Deploy ransom notes on printer' : self.decrypted_main_config[170],
            'unk6' : self.decrypted_main_config[171],
            'Set BlackMatter default icon' : self.decrypted_main_config[172],
            'Contact C2' : self.decrypted_main_config[173],
            'Load worker executable for secure self erase' : self.decrypted_main_config[174],
            'Kill services from inline hashes' : self.decrypted_main_config[175],
            'Load worker to overwrite all data on disk' : self.decrypted_main_config[176],
            'Try lateral movement via network shares' : self.decrypted_main_config[177],
            'Try lateral movement via GPO' : self.decrypted_main_config[178],
            'Push GPO updates immediately' : self.decrypted_main_config[179],
            'Load worker to shutdown system' : self.decrypted_main_config[180],
            'Disable and delete event logs' :  self.decrypted_main_config[181],
            'unk8' : self.decrypted_main_config[182],
            }
        self.conflig_flags = config_flags
        return config_flags


    def decode_base64_strings(self) -> dict:
        """
        Returns the dword offset from the decrypted configuration that referenced the base 64 string and the base64 string in a list of tuples.
        """
        if self.decrypted_main_config is None:
            print("Configuration must be decrypted first")
            return None
        b64_conf_start = 184
        array_of_b64_str_idx_size = 10
        
        configDwordOffset_b64Decoded = []
        for b64_idx in range(b64_conf_start, (b64_conf_start+array_of_b64_str_idx_size*4), 4):
            offset = struct.unpack("<I", self.decrypted_main_config[b64_idx:b64_idx+4])[0]
            if offset:
                offset += 184 # The indexes are at config base + 184
                decoded_b64 = base64.b64decode(self.decrypted_main_config[offset:])
                configDwordOffset_b64Decoded.append(decoded_b64)
            else:
                configDwordOffset_b64Decoded.append(0)


        # whitelisted directory hashes
        if configDwordOffset_b64Decoded[0]:
            configDwordOffset_b64Decoded[0] = [hex(item) for item in self._raw_hashlist_to_hashes(configDwordOffset_b64Decoded[0])]

        #whitelisted filename hashes
        if configDwordOffset_b64Decoded[1]:
            configDwordOffset_b64Decoded[1] = [hex(item) for item in self._raw_hashlist_to_hashes(configDwordOffset_b64Decoded[1])]

        #whitelisted file extension hashes
        if configDwordOffset_b64Decoded[2]:
            configDwordOffset_b64Decoded[2] = [hex(item) for item in self._raw_hashlist_to_hashes(configDwordOffset_b64Decoded[2])]

        # computers whitelisted from rebooting in safemode
        if configDwordOffset_b64Decoded[3]:
            configDwordOffset_b64Decoded[3] = [hex(item) for item in self._raw_hashlist_to_hashes(configDwordOffset_b64Decoded[3])]


        # I don't know what 4 is, the array element didn't exist in the sample I looked at.

        # processes to kill
        if configDwordOffset_b64Decoded[5]:
            configDwordOffset_b64Decoded[5] = self._extract_unicode(configDwordOffset_b64Decoded[5])
   
        if configDwordOffset_b64Decoded[6]:
            configDwordOffset_b64Decoded[6] = self._extract_unicode(configDwordOffset_b64Decoded[6])

        # C2 domains
        if configDwordOffset_b64Decoded[7]:
            configDwordOffset_b64Decoded[7] = "Extraction method unknown for this element"


        # Credentials for brute force
        if configDwordOffset_b64Decoded[8]:
            configDwordOffset_b64Decoded[8] = self.cust_decrypt(configDwordOffset_b64Decoded[8], len(configDwordOffset_b64Decoded[8])).decode('utf-16')

        
        # ransom note
        if configDwordOffset_b64Decoded[9]:
            configDwordOffset_b64Decoded[9] = self.cust_decrypt(configDwordOffset_b64Decoded[9], len(configDwordOffset_b64Decoded[9])).decode()

        not_present_string = "Not present in sample"

        configDwordOffset_b64Decoded = [item if item else not_present_string for item in configDwordOffset_b64Decoded]
    
        decoded = {'Hashes of whitelisted directories': configDwordOffset_b64Decoded[0],
                   'Hashes of whitelisted files' : configDwordOffset_b64Decoded[1],
                   'Hashes of whitelisted file extensions' : configDwordOffset_b64Decoded[2],
                   'Hashes of computer names to not reboot in Safe Mode' : configDwordOffset_b64Decoded[3],
                   'Processes to kill' : configDwordOffset_b64Decoded[5],
                   'Services to kill' : configDwordOffset_b64Decoded[6],
                   'C2 Domains' : configDwordOffset_b64Decoded[7],
                   'Credentials for brute force' : configDwordOffset_b64Decoded[8],
                   'Ransom Note' : configDwordOffset_b64Decoded[9]
                   }

        self.b64_decoded = decoded        
        return decoded    

    
    def extract_all(self):
        if not self.b64_decoded:
            self.decode_base64_strings()
        if not self.conflig_flags:
            self.extract_config_flags()
        if not self.extract_public_rsa():
            self.extract_public_rsa()
        self.extracted_all = self.rsa | self.conflig_flags | self.b64_decoded
        return self.extracted_all
        


    def _raw_hashlist_to_hashes(self, hashlist: bytes) -> list[int]:
        hashes = [hashlist[i:i+4] for i in range(0, len(hashlist), 4)]
        hashes = [struct.unpack("<I", hash)[0] for hash in hashes]
        hashes = [hash for hash in hashes if hash]
        return hashes
    
    def _extract_unicode(self, data: bytes) -> list[str]:
        chunks = []
        current = []
        for i in range(0, len(data), 2):  # UTF-16 uses 2 bytes per char
            try:
                char = data[i:i+2].decode('utf-16')
                current.append(char)
            except UnicodeDecodeError:
                if current:
                    chunks.append(''.join(current))
                    current = []

        if current:
            chunks.append(''.join(current))
        strings_list = [s for s in chunks[0].split('\x00') if s]
        return strings_list
        


if __name__ == "__main__":
    fpath = r"C:\Users\Kevin\Desktop\Samples\Blackmatter\374f9df39b92ccccae8a9b747e606aebe0ddaf117f8f6450052efb5160c99368\374f9df39b92ccccae8a9b747e606aebe0ddaf117f8f6450052efb5160c99368.bin"
    bm = BlackMatterDecryptor(fpath)
    bm.decrypt_config()