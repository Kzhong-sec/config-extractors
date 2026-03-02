import sys
import re
import json
from collections import Counter
import speakeasy
import idaapi
from ida_domain import Database
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad


def aes_cbc_decrypt(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = cipher.decrypt(ciphertext)
    plaintext = unpad(plaintext, AES.block_size)
    return plaintext

first_alloc = None

class MyEmu(speakeasy.Speakeasy):

    def __init__(self):
        super().__init__()

        self.heap_called = False

        self.add_api_hook(
            self.heapalloc_hook,
            "kernel32",
            "HeapAlloc"
        )


    def heapalloc_hook(self, emu, api_name, func, params):
        global first_alloc
        # call real HeapAlloc
        heap_alloc_addr = func(params)
        if first_alloc is None:
            size = params[2]
            first_alloc = (heap_alloc_addr, size)

        return heap_alloc_addr

def find_shellcode_func(fpath):
    db = Database() # run from IDA gui. need IDA pro to use IDA domain outside GUI
    all_strings = db.strings.get_all()

    string_addr = None
    for s in all_strings:
        if s.contents == b'ZwAllocateVirtualMemory':
            string_addr = s.address

    data_seg = db.segments.get_by_name(".data")

    start_ea = None
    key_candidates = []

    if string_addr:
        refs = list(db.xrefs.data_refs_to_ea(string_addr))
        if len(refs) != 1:
            raise Exception("Unexpected amount of references to ZwAllocateVirtualMemory string")
        func = db.functions.get_at(refs[0])
        start_ea = func.start_ea
        insns = db.functions.get_instructions(func)
        for i in insns:
            if db.instructions.get_mnemonic(i) == 'push':
                op = db.instructions.get_operand(i, 0)
                if op.type == idaapi.o_imm:
                    val = op.get_value()
                    if data_seg.start_ea <= val <= data_seg.end_ea:
                        key_candidates.append(idaapi.get_bytes(val, 16))
    if start_ea and key_candidates:
        return (start_ea, key_candidates)
    else:
        raise Exception("Could not get functions start address or key candidates")


def extract_shellcode(func_addr, fpath):
    se = MyEmu()
    module = se.load_module(fpath)
    se.run_module(module)
    se.call(func_addr)
    data = se.mem_read(first_alloc[0], first_alloc[1]) # heap alloc addr, heap alloc size
    iv = data[:16]
    payload = data[16:]
    return (iv, payload)


def xor_with_key(buf, key):
    return bytes(b ^ key for b in buf)

ip_regex = re.compile(
    rb"^(?:\d{1,3}\.){3}\d{1,3}\x00"
)

def valid_ip_at_start(buf):
    m = ip_regex.match(buf)
    if not m:
        return False
    ip = m.group()[:-1]  # remove null
    parts = ip.split(b".")
    for p in parts:
        if int(p) > 255:
            return False
    return True

def xor_brute_force(data):
    for k in range(256):
        out = xor_with_key(data, k)
        if valid_ip_at_start(out):
            print(f"[+] key = {k:#x}")
            return out
    raise Exception("Unable to decrypt config")

def extract_config(config):  # config should be decrypted

    # ---- port ----
    port_bytes = config[300:302]
    port = int.from_bytes(port_bytes, byteorder="little")

    # ---- ip ----
    null_pos = config.find(b"\x00")
    ip_bytes = config[:null_pos]
    ip_str = ip_bytes.decode("ascii", errors="ignore")

    # ---- target image ----
    start = config.find(b"C:\\")
    if start == -1:
        target_image = None
    else:
        end = config.find(b"\x00", start)
        target_image = config[start:end].decode("ascii", errors="ignore")

    result = {
        "ip": ip_str,
        "port": port,
        "target_image": target_image,
    }

    return json.dumps(result, indent=4)
    
def main():
    if len(sys.argv) != 2:
        print("usage: script.py <sample>")
        sys.exit(1)

    fpath = sys.argv[1]
    start_ea, key_candidates = find_shellcode_func(fpath)
    iv, payload = extract_shellcode(start_ea, fpath)
    for key in key_candidates:
        try:
            dec = aes_cbc_decrypt(payload, key, iv)
        except:
            pass
        if dec[:3] == b'\x55\x8b\xec': # pushEbp, movEbpEsp
            break

    marker = b'godinfo'
    offset = dec.find(marker)
    enc_config = dec[offset+len(marker):]
    xor_key_candidate = Counter(enc_config).most_common(1)[0][0] # most common byte
    dec = xor_with_key(enc_config, xor_key_candidate)
    if not valid_ip_at_start(dec):
        dec = xor_brute_force(enc_config)

    print(extract_config(dec))

main()