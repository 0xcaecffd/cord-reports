// Targeted retrohunt rules for the lineage of 0c5486f06620e26e316f4b33f318b0d646d5e1133789331aa2fed012360d1486
// (CORD, potassium lineage, 2026-10-22). Build-independent marks only:
// every constant that the builder changes between builds (mask byte, port, keys, hosts) is wildcarded.
// Tested 2026-10-22 on 16,686 ELF samples (10,509 of them Mirai-labelled), 4,699 Linux
// system binaries and 1,542 Windows goodware files: no goodware matches.

rule elf_mirai_ext_x64_build_family
{
    meta:
        description = "x86-64 builds of the sample's own code generation: 0xdeaffed frame constant, one-byte XOR plain mode, masked-constant derivation loops, loopback single-instance lock"
        source = "CORD potassium lineage set 2026-10-22, rule 1 of 4 (tight)"
        confidence = "medium"
        severity = 70
    strings:
        $deaffed  = { BA ED FF EA 0D }                                  // mov $0xdeaffed,%edx (plain-mode XOR seed)
        $plainxor = { 30 14 07 48 FF C0 EB F4 C3 }                      // xor %dl,(%rdi,%rax); inc; jmp; ret
        $keyderiv = { 0F AF C7 83 ?? ?? 32 04 16 88 }                   // (i*k1 +/- k2) ^ table[i] byte derivation
        $unmask   = { 83 F1 ?? 88 [2-3] 48 83 F8 10 75 }                // 16-byte xor-with-immediate unmask loop
        $frametyp = { 8A 04 38 83 F0 ?? C3 }                            // masked frame-type byte lookup
        $lock     = { BF 01 00 00 7F E8 ?? ?? ?? ?? BF ?? ?? 00 00 89 44 24 ?? 41 BC ?? 00 00 00 }
        $mt64     = { 00 00 00 00 00 00 00 00 ?? ?? ?? ?? 00 00 00 00 01 00 00 00 00 00 00 00 ?? ?? ?? ?? 00 00 00 00 02 00 00 00 00 00 00 00 ?? ?? ?? ?? 00 00 00 00 03 00 00 00 00 00 00 00 ?? ?? ?? ?? 00 00 00 00 04 00 00 00 00 00 00 00 ?? ?? ?? ?? 00 00 00 00 05 00 00 00 00 00 00 00 ?? ?? ?? ?? 00 00 00 00 06 00 00 00 00 00 00 00 ?? ?? ?? ?? 00 00 00 00 07 00 00 00 00 00 00 00 ?? ?? ?? ?? 00 00 00 00 08 00 00 00 00 00 00 00 ?? ?? ?? ?? 00 00 00 00 09 00 00 00 00 00 00 00 ?? ?? ?? ?? 00 00 00 00 0A 00 00 00 00 00 00 00 ?? ?? ?? ?? 00 00 00 00 0B 00 00 00 00 00 00 00 }
    condition:
        uint32(0) == 0x464C457F and uint8(4) == 2 and uint16(16) == 2 and uint16(18) == 62
        and filesize < 2MB
        and ( 2 of ($deaffed, $plainxor, $keyderiv, $unmask, $frametyp, $lock)
              or ( 1 of ($deaffed, $plainxor, $keyderiv, $unmask, $frametyp, $lock) and $mt64 ) )
}
