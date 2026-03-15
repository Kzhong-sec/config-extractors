import idautils
import idaapi
import ida_ua
from ida_domain import Database

db = Database()
def to_signed_32(x):
    x &= 0xFFFFFFFF          # ensure 32-bit
    if x & 0x80000000:       # if sign bit set
        x -= 0x100000000
    return x
    
def get_sibling_block_from_c(ea_in_c):
    """
    Given an address inside block C,
    returns the start_ea of the sibling block (B)
    that shares the same predecessor (A).
    """

    func = idaapi.get_func(ea_in_c)
    if not func:
        return None

    flow = idaapi.FlowChart(func)

    # Find block C
    block_c = None
    for block in flow:
        if block.start_ea <= ea_in_c < block.end_ea:
            block_c = block
            break

    if not block_c:
        return None

    # For each predecessor of C
    for pred in block_c.preds():
        # For each successor of that predecessor
        for succ in pred.succs():
            # Return the one that is NOT C
            if succ.start_ea != block_c.start_ea:
                return succ.start_ea

    return None

def next_head_until_call(ea):
    """
    Returns the address of the next CALL instruction
    starting from ea.
    Stops at function end.
    """

    func = idaapi.get_func(ea)
    if not func:
        return None

    end = func.end_ea

    while ea < end:
        insn = ida_ua.insn_t()
        size = ida_ua.decode_insn(insn, ea)

        if size <= 0:
            ea = idaapi.next_head(ea, end)
            continue

        if insn.get_canon_mnem() == "call":
            return ea

        ea = idaapi.next_head(ea, end)

    return None

def find_pattern():
    addrs = {}
    print("[*] Searching for MOV -> XOR -> MOV -> ADD -> JMP patterns...\n")

    for func_ea in idautils.Functions():
        func = idaapi.get_func(func_ea)
        if not func:
            continue

        ea = func.start_ea
        end = func.end_ea

        while ea < end:
            insn1 = ida_ua.insn_t()
            if not ida_ua.decode_insn(insn1, ea):
                ea += 1
                continue

            if insn1.get_canon_mnem() == "mov":
                enc_loc_operand = db.instructions.get_operand(insn1, 1)
                ea2 = ea + insn1.size
                insn2 = ida_ua.insn_t()
                if ida_ua.decode_insn(insn2, ea2) and insn2.get_canon_mnem() == "xor":

                    ea3 = ea2 + insn2.size
                    insn3 = ida_ua.insn_t()
                    if ida_ua.decode_insn(insn3, ea3) and insn3.get_canon_mnem() == "mov":
                        buf_operand = db.instructions.get_operand(insn3, 0)

                        ea4 = ea3 + insn3.size
                        insn4 = ida_ua.insn_t()
                        if ida_ua.decode_insn(insn4, ea4) and insn4.get_canon_mnem() == "add":

                            ea5 = ea4 + insn4.size
                            insn5 = ida_ua.insn_t()
                            emu_end = get_sibling_block_from_c(ea5)
                            if ida_ua.decode_insn(insn5, ea5) and insn5.get_canon_mnem() == "jmp":
                                enc_loc = enc_loc_operand.get_address()
                                base_reg = buf_operand.get_formatted_string()
                                base_reg = base_reg[1:4]
                                disp = to_signed_32(buf_operand.get_displacement())
                                addrs[ea] = {
                                "base_reg" : base_reg,
                                "disp" : disp,
                                "emu_end" : emu_end,
                                "enc_loc" : enc_loc
                                }

            ea += insn1.size
    return addrs


def get_basic_block_start(ea):
    func = idaapi.get_func(ea)
    if not func:
        return None

    flow = idaapi.FlowChart(func)

    for block in flow:
        if block.start_ea <= ea < block.end_ea:
            return block.start_ea

    return None



def find_previous_call(ea):
    # Get current cursor address


    # Walk backwards byte-by-byte
    while ea > 0:
        insn = ida_ua.insn_t()
        size = ida_ua.decode_insn(insn, ea)

        # If valid instruction
        if size > 0:
            if insn.get_canon_mnem() == "call":
                return ea

            # Move backwards
            ea -= 1
        else:
            ea -= 1

    print("[-] No CALL found before current location.")
    
    return None



def step_back_until_call_or_target(ea, target_ea):

    while ea > 0:

        # Stop if we reached the target
        if ea == target_ea:
            return ea

        # Decode instruction at current address
        insn = ida_ua.insn_t()
        size = ida_ua.decode_insn(insn, ea)

        if size > 0:
            # Stop early if CALL found
            if insn.get_canon_mnem() == "call":
                ea = idc.next_head(ea)
                return ea

            # Move backwards
            ea -= 1
        else:
            ea -= 1

    return None



import angr
import sys



def print_eip(state):
    print(f"EIP : {hex(state.solver.eval(state.regs.eip))}")

def print_context(state):
    print(f"EIP : {hex(state.solver.eval(state.regs.eip))}")
    print(f"ESI : {hex(state.solver.eval(state.regs.esi))}")
    print(f"EDX : {hex(state.solver.eval(state.regs.edx))}")
    print(f"ECX : {hex(state.solver.eval(state.regs.ecx))}")
    print(f"ESP : {hex(state.solver.eval(state.regs.esp))}")
    print(f"EBP : {hex(state.solver.eval(state.regs.ebp))}")
    print(f"EBX : {hex(state.solver.eval(state.regs.ebx))}")
    print(f"EAX : {hex(state.solver.eval(state.regs.eax))}")
    print(f"EDI : {hex(state.solver.eval(state.regs.edi))}")
    print("\n")

def hook_func(state):
    buf = state.memory.load(state.solver.eval(state.regs.edi), 100)
    payload = state.solver.eval(buf, cast_to=bytes)
    print(payload)
    
def emulate(start, end, proj, hook_func=print_context, silent=True):
    s = proj.factory.full_init_state() # important to fill out globals and such pretty pretty sure
    s.regs.eip = start
    s.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS)
    s.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY)

    
    simgr = proj.factory.simulation_manager(s)
    s = simgr.active[0]

    block = proj.factory.block(end)
    bb_start = block.addr
    bb_end = block.addr + block.size

    while True:
        #print(len(simgr.active))
        # Print context for each basic block
        if silent == False:
            print_context(s)
            #print_eip(s)
            # Check if target address reached
        if bb_start <= s.addr <= bb_end:
            print_eip(s)
            print(f"Target address reached!")
            break
        succ = s.step().successors
        #print(len(succ)) # verifying its not doing any actual symex, just emulating, only one state at a time
        s = succ[0]
    return s
    #si = s.solver.eval(s.regs.esi)
    #buf_len = 0x1e0*4
    #buf = esi-buf_len
    #buf = (s.memory.load(buf, buf_len))
    #payload = s.solver.eval(buf, cast_to=bytes)
    #print(payload)



def bytes_until_null(data: bytes) -> str:
    null_index = data.find(b'\x00')
    
    if null_index == -1:
        null_index = len(data)

    return data[:null_index].decode("utf-8", errors="ignore")
    
def main():
    fpath = r"C:\Users\Kevin\Desktop\Samples\RustyClaw\b1fe8fbbb0b6de0f1dcd4146d674a71c511488a9eb4538689294bd782df040df\b1fe8fbbb0b6de0f1dcd4146d674a71c511488a9eb4538689294bd782df040df"
    proj = angr.Project(fpath, auto_load_libs=False)

    values = find_pattern()
    str_list = []
    for addr in values:
        
        base_reg = values[addr]["base_reg"]
        disp = values[addr]["disp"]
        emu_end = values[addr]["emu_end"]
        emu_end = next_head_until_call(emu_end)
        enc_loc = values[addr]["enc_loc"]
        
        proj.hook(emu_end, hook_func)
        prev_call = find_previous_call(addr)
        target = get_basic_block_start(prev_call)
        prev_call -= 1

        emu_start = step_back_until_call_or_target(prev_call, target)
        print(f"emulating from {hex(emu_start)}")
        s = emulate(emu_start, emu_end, proj)
        buf = s.memory.load(s.solver.eval(getattr(s.regs, base_reg) + disp), 100)
        buf = s.solver.eval(buf, cast_to=bytes)
        dec_str = bytes_until_null(buf)
        str_list.append(dec_str)
        db.names.force_name(enc_loc, dec_str)
        db.bytes.patch_bytes_at(enc_loc, dec_str.encode())
        print(f"string {dec_str} at {hex(enc_loc)}")
        
    for st in str_list:
        print(st)
        

main()