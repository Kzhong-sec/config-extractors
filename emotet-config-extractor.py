from unicorn import *
from unicorn.x86_const import *
import struct
from capstone import *
import pefile
import re
import ctypes
import sys

ips = []
cap = Cs(CS_ARCH_X86, CS_MODE_64)
ALLOCATION_CHUNK_SIZE = 0x1000


def hook_code(uc, address, size, user_data):
    cur_code = uc.mem_read(address, size)
    instructions = cap.disasm(cur_code, address)
    for instruction in instructions:
        #print(f"{hex(instruction.address)}\t{instruction.mnemonic}\t{instruction.op_str}")
        if instruction.mnemonic == 'retn' or instruction.mnemonic == 'ret':
            out = uc.mem_read(0x10000, 4)
            ip = ''
            for byte in out:
                ip += str(byte)
                ip += '.'
            ip = ip[:-1]
            ips.append(ip)
            print(ip)
            uc.emu_stop()
        if instruction.mnemonic == 'call':
            uc.emu_stop()


def emulate_ip_resolver(code, address):
    uc = Uc(UC_ARCH_X86, UC_MODE_64)
    uc.hook_add(UC_HOOK_CODE, hook_code)
    uc.mem_map(0x10000, 0x1000, UC_PROT_ALL)
    uc.mem_map(0x20000, 0x1000, UC_PROT_ALL)
    uc.reg_write(UC_X86_REG_RCX, 0x10000)
    uc.reg_write(UC_X86_REG_RDX, 0x20000)

    emulate_func(uc, code, address)


def emulate_func(uc: Uc, code: bytes, code_base_ptr: int):
    # Allocating memory for the code, and writing it
    allocation_base = code_base_ptr & 0b1111_1111_1111_1111_1111_1111_1111_1111_0000_0000_0000_0000 # alligns the allocation base with 0x1000, was getting unicorn memory errors, not sure if this is required, or if it was the issue.
    uc.mem_map(allocation_base, ALLOCATION_CHUNK_SIZE, UC_PROT_ALL)
    uc.mem_write(allocation_base, b'\x00' * ALLOCATION_CHUNK_SIZE)
    allocation_end = allocation_base + ALLOCATION_CHUNK_SIZE
    # Allocates more memory if the allocated memory is not enough for the function
    code_len = len(code)
    while (code_len + code_base_ptr) > allocation_end: 
        uc.mem_map(allocation_end, ALLOCATION_CHUNK_SIZE, UC_PROT_ALL)
        uc.mem_write(allocation_end, b'\x00' * ALLOCATION_CHUNK_SIZE)
        allocation_end += ALLOCATION_CHUNK_SIZE
    uc.mem_write(code_base_ptr, code)

    # initialising some stack space. Not doing any memory checks with this. Not sure how you even could, and the stack space required by a function should never exceed this
    STACK_SPACE = 0x2000
    uc.mem_map(STACK_SPACE, ALLOCATION_CHUNK_SIZE, UC_PROT_ALL)
    uc.mem_write(STACK_SPACE, b'\x00' * ALLOCATION_CHUNK_SIZE)
    uc.reg_write(UC_X86_REG_ESP, STACK_SPACE + ALLOCATION_CHUNK_SIZE // 2) # intialises the stack pointer in the middle of the allocated stack space - Makes it easy to intialise arguements if required.
    
    print("emu start")
    uc.emu_start(code_base_ptr, code_base_ptr + len(code), timeout = 0, count = 0)
    print("Finished Emulating")


def retrieve_func_addrs(pe):
    image_base = pe.OPTIONAL_HEADER.ImageBase
    for section in pe.sections:
        if b'.text' in section.Name:
            emotet_content = section.get_data()
            text_rva = section.VirtualAddress
    find_lea = re.compile(rb'\x48\x8d\x05(.{4})\x48\x89')
    matches = find_lea.finditer(emotet_content)

    func_addrs = []

    for match in matches:
        offset = match.group(1)
        offset = struct.unpack("<I", offset)[0]
        offset = ctypes.c_int(offset).value
        VA = match.start()
        VA += text_rva + image_base
        func_addr = VA + offset + 7
        func_addrs.append(func_addr)

    return func_addrs

def main():
    if len(sys.argv) < 2:
        print("Usage: python script.py <file_path>")
        sys.exit(1)
    pe = pefile.PE(sys.argv[1])
    image_base = pe.OPTIONAL_HEADER.ImageBase

    func_addrs = retrieve_func_addrs(pe)
    func_code_list = (pe.get_data(func_addr - image_base, 0x1000) for func_addr in func_addrs)

    for func_code in func_code_list:
        try:
            emulate_ip_resolver(func_code, 0x40_000)
            print()
        except:
            pass

    print(ips)

main()
