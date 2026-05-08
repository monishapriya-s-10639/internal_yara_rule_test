rule CobaltStrike_Resources_Beacon_Dll_v3_2
{
  meta:
    description = "Cobalt Strike's resources/beacon.dll Versions 3.2"
    hash = "b490eeb95d150530b8e155da5d7ef778543836a03cb5c27767f1ae4265449a8d"
    rs2 ="a93647c373f16d61c38ba6382901f468247f12ba8cbe56663abb2a11ff2a5144"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"

    id = "3ccbc0f2-241c-5c10-8930-4a3d264d3b57"
  strings:
    /*
      48                dec     eax; switch 62 cases
      57                push    edi
      8B F2             mov     esi, edx
      83 F8 3D          cmp     eax, 3Dh
      0F 87 83 02 00 00 ja      def_10001130; jumptable 10001130 default case, cases 6-8,30
      FF 24 ??          jmp     ds:jpt_10001130[eax*4]; switch jump
    */
    $version_sig = { 48 57 8B F2 83 F8 3D 0F 87 83 02 00 00 FF 24 }

    /*
      80 B0 [4] 69   xor     byte ptr word_1002C040[eax], 69h
      40             inc     eax
      3D 10 06 00 00 cmp     eax, 610h
      72 F1          jb      short loc_1000674A
    */
    $decoder = { 80 B0 [4] ?? 40 3D 10 06 00 00 72 F1 }

    // Since v3.1 and v3.2 are so similiar, we use the v3.1 version_sig
    // as a negating condition to diff between 3.1 and 3.2
    /*
      55             push    ebp
      8B EC          mov     ebp, esp
      83 EC 58       sub     esp, 58h
      A1 [4]         mov     eax, ___security_cookie
      33 C5          xor     eax, ebp
      89 45 FC       mov     [ebp+var_4], eax
      E8 DF F5 FF FF call    sub_10002109
      6A 50          push    50h ; 'P'; namelen
      8D 45 A8       lea     eax, [ebp+name]
      50             push    eax; name
      FF 15 [4]      call    ds:gethostname
      8D 45 ??       lea     eax, [ebp+name]
      50             push    eax; name
      FF 15 [4]      call    ds:__imp_gethostbyname
      85 C0          test    eax, eax
      74 14          jz      short loc_10002B58
      8B 40 0C       mov     eax, [eax+0Ch]
      83 38 00       cmp     dword ptr [eax], 0
      74 0C          jz      short loc_10002B58
      8B 00          mov     eax, [eax]
      FF 30          push    dword ptr [eax]; in
      FF 15 [4]      call    ds:inet_ntoa
      EB 05          jmp     short loc_10002B5D
      B8 [4]         mov     eax, offset aUnknown; "unknown"
      8B 4D FC       mov     ecx, [ebp+var_4]
      33 CD          xor     ecx, ebp; StackCookie
      E8 82 B7 00 00 call    @__security_check_cookie@4; __security_check_cookie(x)
      C9             leave
    */
    $version3_1_sig = { 55 8B EC 83 EC 58 A1 [4] 33 C5 89 45 FC E8 DF F5 FF FF 6A 50 8D 45 A8 50 FF 15 [4] 8D 45 ?? 50 FF 15 [4] 85 C0 74 14 8B 40 0C 83 38 00 74 0C 8B 00 FF 30 FF 15 [4] EB 05 B8 [4] 8B 4D FC 33 CD E8 82 B7 00 00 C9 }

  condition:
    $version_sig and $decoder and not $version3_1_sig
}
