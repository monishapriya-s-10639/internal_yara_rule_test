import "pe"

rule apt_Windows_TA410_FlowCloud_shellcode_decryption
{
    meta:
        description = "Matches the decryption function used in TA410 FlowCloud self-decrypting DLL"
        reference = "https://www.welivesecurity.com/"
        source = "https://github.com/eset/malware-ioc/"
        license = "BSD 2-Clause"
        version = "1"
        author = "ESET Research"
        date = "2021-10-12"
    /*
    0x211 33D2              xor edx, edx
    0x213 8B4510            mov eax, dword ptr [ebp + 0x10]
    0x216 BB6B040000            mov ebx, 0x46b
    0x21b F7F3              div ebx
    0x21d 81C2A8010000          add edx, 0x1a8
    0x223 81E2FF000000          and edx, 0xff
    0x229 8B7D08            mov edi, dword ptr [ebp + 8]
    0x22c 33C9              xor ecx, ecx
    0x22e EB07              jmp 0x237
    0x230 301439            xor byte ptr [ecx + edi], dl
    0x233 001439            add byte ptr [ecx + edi], dl
    0x236 41                inc ecx
    0x237 3B4D0C            cmp ecx, dword ptr [ebp + 0xc]
    0x23a 72F4              jb 0x230
     */
    strings:
        $chunk_1 = {
            33 D2
            8B 45 ??
            BB 6B 04 00 00
            F7 F3
            81 C2 A8 01 00 00
            81 E2 FF 00 00 00
            8B 7D ??
            33 C9
            EB ??
            30 14 39
            00 14 39
            41
            3B 4D ??
            72 ??
        }

    condition:
        uint16(0) == 0x5a4d and all of them
}
