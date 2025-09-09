
; DLL creation example
format PE GUI 4.0 DLL
entry DllEntryPoint
include 'win32a.inc'
section '.text' code readable executable
proc DllEntryPoint hinstDLL,fdwReason,lpvReserved
        mov     eax,TRUE
        ret
endp


        ; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame info_from_lumina

; __int64 __stdcall calc_number(__int64, __int64)
proc            calc_number        ; CODE XREF: prng+18↓p prng+37↓p

arg_0           equ 8
arg_8           equ 10h

                push    ebp
                mov     ebp, esp
                push    ecx
                push    ebx
                mov     eax, [ebp+arg_0+4]
                mov     ecx, [ebp+arg_8+4]
                or      ecx, eax
                mov     ecx, [ebp+arg_8]
                jnz     short loc_1006A
                mov     eax, [ebp+arg_0]
                mul     ecx
                pop     ebx
                pop     ecx
                pop     ebp
                retn    10h
; ---------------------------------------------------------------------------

loc_1006A:                              ; CODE XREF: calc_number+10↑j
                mul     ecx
                mov     ebx, eax
                mov     eax, [ebp+arg_0]
                mul     dword [ebp+arg_8+4]
                add     ebx, eax
                mov     eax, [ebp+arg_0]
                mul     ecx
                add     edx, ebx
                pop     ebx
                pop     ecx
                pop     ebp
                retn    10h
endp


; =============== S U B R O U T I N E =======================================


; __int64 __stdcall prng(__int64 *pseed, __int64 *pseed_2)
proc            prng

pseed           equ  8
pseed_2         equ  0Ch

                push    ebp
                mov     ebp, esp
                push    ebx
                mov     ebx, [ebp+pseed_2]
                mov     eax, [ebx]
                mov     edx, [ebx+4]
                push    5851F42Dh
                push    4C957F2Dh       ; __int64
                push    edx
                push    eax             ; __int64
                call    calc_number
                add     eax, 0F767814Fh
                adc     edx, 14057B7Eh
                mov     [ebx], eax
                mov     [ebx+4], edx
                mov     ebx, [ebp+pseed]
                push    edx
                push    eax             ; __int64
                push    dword [ebx+4]
                push    dword [ebx] ; __int64
                call    calc_number
                pop     ebx
                pop     ebp
                retn    8
endp






; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame info_from_lumina

; unsigned int __stdcall __spoils<eax> cust_decrypt(_BYTE *cur_char___, int size)
proc            bmatter_decrypt       ; CODE XREF: decrypt_buffer+22↓p
                                        ; custTwoWayEncDecrypt+2B↓p
                                        ; decrypt_config+290↓p
                                        ; decrypt_config+2C9↓p
                                        ; brute_force_and_try_logon_domain_admins+4C↓p
                                        ; sub_40BB94+19C↓p ...

a2              equ -0Ch
var_8           equ -8
var_4           equ -4
cur_char___     equ 8 ; this is buffer input
size            equ 0Ch
key             equ 10h


                push    ebp
                mov     ebp, esp
                add     esp, 0FFFFFFF4h
                push    ebx
                push    ecx
                push    esi
                mov     ebx, [ebp+size]
                mov     esi, [ebp+cur_char___]
                mov     eax, [ebp+key]
                lea     eax, [eax]
                mov     edx, [eax+4]
                mov     eax, [eax]
                mov     dword [ebp+a2], eax
                mov     dword [ebp+var_8], edx

loc_401750:                             ; CODE XREF: cust_decrypt+88↓j
                lea     eax, [ebp+a2]
                push    eax
                mov     eax, [ebp+key]  ; a1
                push    eax
                call    prng
                mov     dword [ebp+var_4], 2

loc_401765:                             ; CODE XREF: cust_decrypt+86↓j
                xor     [esi], al
                inc     esi
                dec     ebx
                test    ebx, ebx
                jnz     short loc_401776
                pop     esi
                pop     ecx
                pop     ebx
                mov     esp, ebp
                pop     ebp
                retn    8
; ---------------------------------------------------------------------------

loc_401776:                             ; CODE XREF: cust_decrypt+3B↑j
                xor     [esi], dh
                inc     esi
                dec     ebx
                test    ebx, ebx
                jnz     short loc_401787
                pop     esi
                pop     ecx
                pop     ebx
                mov     esp, ebp
                pop     ebp
                retn    8
; ---------------------------------------------------------------------------

loc_401787:                             ; CODE XREF: cust_decrypt+4C↑j
                xor     [esi], ah
                inc     esi
                dec     ebx
                test    ebx, ebx
                jnz     short loc_401798
                pop     esi
                pop     ecx
                pop     ebx
                mov     esp, ebp
                pop     ebp
                retn    8
; ---------------------------------------------------------------------------

loc_401798:                             ; CODE XREF: cust_decrypt+5D↑j
                xor     [esi], dl
                inc     esi
                dec     ebx
                test    ebx, ebx
                jnz     short loc_4017A9
                pop     esi
                pop     ecx
                pop     ebx
                mov     esp, ebp
                pop     ebp
                retn    8
; ---------------------------------------------------------------------------

loc_4017A9:                             ; CODE XREF: cust_decrypt+6E↑j
                shr     eax, 10h
                shr     edx, 10h
                dec     dword [ebp+var_4]
                cmp     dword [ebp+var_4], 0
                jnz     short loc_401765
                jmp     short loc_401750
endp        ; sp-analysis failed

; ---------------------------------------------------------------------------









section '.edata' export data readable
  export 'BMATTER_DECRYPT.DLL',\
         bmatter_decrypt,'bmatter_decrypt'

section '.reloc' fixups data readable discardable
  if $=$$
    dd 0,8              ; if there are no fixups, generate dummy entry
  end if
