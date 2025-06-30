import idautils
import idaapi
#need to go back and actally find how to extract it.

enc_data_cur_ptr = 0x180008000
dec_data = bytearray()
for i in range(256):
    a = idaapi.get_byte(enc_data_cur_ptr)
    a ^= idaapi.get_byte(enc_data_cur_ptr + 64)
    dec_data.append(a)
    enc_data_cur_ptr += 1
    
print(dec_data)