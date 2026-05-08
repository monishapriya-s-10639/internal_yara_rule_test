rule Stuxnet_s7hkimdb {
	meta:
		description = "Stuxnet Sample - file s7hkimdb.dll"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Internal Research"
		date = "2016-07-09"
		hash1 = "4071ec265a44d1f0d42ff92b2fa0b30aafa7f6bb2160ed1d0d5372d70ac654bd"
		id = "e4cb277f-5eee-5405-9d48-d06657392323"
	strings:
		$x1 = "S7HKIMDX.DLL" fullword wide

		/* Opcodes by Binar.ly */

		// 0x10001778 8b 45 08  mov     eax, dword ptr [ebp + 8]
		// 0x1000177b 35 dd 79 19 ae    xor     eax, 0xae1979dd
		// 0x10001780 33 c9     xor     ecx, ecx
		// 0x10001782 8b 55 08  mov     edx, dword ptr [ebp + 8]
		// 0x10001785 89 02     mov     dword ptr [edx], eax
		// 0x10001787 89 ?? ??  mov     dword ptr [edx + 4], ecx
		$op1 = { 8b 45 08 35 dd 79 19 ae 33 c9 8b 55 08 89 02 89 }
		// 0x10002045 74 36     je      0x1000207d
		// 0x10002047 8b 7f 08  mov     edi, dword ptr [edi + 8]
		// 0x1000204a 83 ff 00  cmp     edi, 0
		// 0x1000204d 74 2e     je      0x1000207d
		// 0x1000204f 0f b7 1f  movzx   ebx, word ptr [edi]
		// 0x10002052 8b 7f 04  mov     edi, dword ptr [edi + 4]
		$op2 = { 74 36 8b 7f 08 83 ff 00 74 2e 0f b7 1f 8b 7f 04 }
		// 0x100020cf 74 70     je      0x10002141
		// 0x100020d1 81 78 05 8d 54 24 04      cmp     dword ptr [eax + 5], 0x424548d
		// 0x100020d8 75 1b     jne     0x100020f5
		// 0x100020da 81 78 08 04 cd ?? ??      cmp     dword ptr [eax + 8], 0xc22ecd04
		$op3 = { 74 70 81 78 05 8d 54 24 04 75 1b 81 78 08 04 cd }

	condition:
		( uint16(0) == 0x5a4d and filesize < 40KB and $x1 and all of ($op*) )
}
