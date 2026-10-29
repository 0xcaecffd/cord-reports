// Targeted retrohunt rules for the lineage of 0c5486f06620e26e316f4b33f318b0d646d5e1133789331aa2fed012360d1486
// (CORD, potassium lineage, 2026-10-22). Build-independent marks only:
// every constant that the builder changes between builds (mask byte, port, keys, hosts) is wildcarded.
// Tested 2026-10-22 on 16,686 ELF samples (10,509 of them Mirai-labelled), 4,699 Linux
// system binaries and 1,542 Windows goodware files: no goodware matches.

rule elf_masked_chacha_constant_survey
{
    meta:
        description = "Survey rule: any ELF under 1 MB holding the ChaCha20/Salsa20 constant under a single-byte XOR mask and no plain copy of it (the sample masks it with 0xa5; a sibling with 0x22 exists); expected to reach beyond the lineage, results need triage"
        source = "CORD potassium lineage set 2026-10-22, rule 4 of 4 (survey)"
        confidence = "low"
        severity = 30
    strings:
        $sgx = "expand 32-byte k" xor(0x01-0xff)
        $sig = "expand 32-byte k"
    condition:
        uint32(0) == 0x464C457F and filesize < 1MB and $sgx and not $sig
}
// Targeted retrohunt rules for the lineage of 0c5486f06620e26e316f4b33f318b0d646d5e1133789331aa2fed012360d1486
// (CORD, potassium lineage, 2026-10-22). Build-independent marks only:
// every constant that the builder changes between builds (mask byte, port, keys, hosts) is wildcarded.
// Tested 2026-10-22 on 16,686 ELF samples (10,509 of them Mirai-labelled), 4,699 Linux
// system binaries and 1,542 Windows goodware files: no goodware matches.

rule elf_mirai_ext_multiarch_literals
{
    meta:
        description = "Any-architecture builds of the lineage by literal-pool constants: the 0xdeaffed frame constant and the 8.8.8.8 local-address probe, both word-aligned, beside a ChaCha constant, a watchdog path or a static attack table"
        source = "CORD potassium lineage set 2026-10-22, rule 3 of 4 (multi-arch)"
        confidence = "low"
        severity = 50
    strings:
        $dle = { ED FF EA 0D }
        $dbe = { 0D EA FF ED }
        $g8  = { 08 08 08 08 }
        $sig = "expand 32-byte k"
        $sgx = "expand 32-byte k" xor(0x01-0xff)
        $wd  = "/dev/misc/watchdog"
        $mt32le = { 00 00 00 00 ?? ?? ?? ?? 01 00 00 00 ?? ?? ?? ?? 02 00 00 00 ?? ?? ?? ?? 03 00 00 00 ?? ?? ?? ?? 04 00 00 00 ?? ?? ?? ?? 05 00 00 00 ?? ?? ?? ?? 06 00 00 00 ?? ?? ?? ?? 07 00 00 00 }
        $mt32be = { 00 00 00 00 ?? ?? ?? ?? 00 00 00 01 ?? ?? ?? ?? 00 00 00 02 ?? ?? ?? ?? 00 00 00 03 ?? ?? ?? ?? 00 00 00 04 ?? ?? ?? ?? 00 00 00 05 ?? ?? ?? ?? 00 00 00 06 ?? ?? ?? ?? 00 00 00 07 }
    condition:
        uint32(0) == 0x464C457F and filesize < 1MB
        and ( for any i in (1..8) : (@dle[i] % 4 == 0) or for any i in (1..8) : (@dbe[i] % 4 == 0) )
        and for any i in (1..16) : (@g8[i] % 4 == 0)
        and 1 of ($sig, $sgx, $wd, $mt32le, $mt32be)
}
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
// Targeted retrohunt rules for the lineage of 0c5486f06620e26e316f4b33f318b0d646d5e1133789331aa2fed012360d1486
// (CORD, potassium lineage, 2026-10-22). Build-independent marks only:
// every constant that the builder changes between builds (mask byte, port, keys, hosts) is wildcarded.
// Tested 2026-10-22 on 16,686 ELF samples (10,509 of them Mirai-labelled), 4,699 Linux
// system binaries and 1,542 Windows goodware files: no goodware matches.

rule elf_mirai_ext_x64_chacha_lineage
{
    meta:
        description = "x86-64 static Mirai derivatives carrying the lineage's ChaCha20 routine (quarter-round calls with state indices as immediates) or a masked ChaCha constant, beside a Mirai mark (8.8.8.8:53 local-address probe, loopback lock, X25519 clamp, static attack table)"
        source = "CORD potassium lineage set 2026-10-22, rule 2 of 4 (lineage)"
        confidence = "medium"
        severity = 60
    strings:
        $qr1      = { 41 B8 0C 00 00 00 B9 08 00 00 00 BA 04 00 00 00 E8 }               // QR(x,0,4,8,12)
        $qr2      = { 41 B8 0D 00 00 00 B9 09 00 00 00 BA 05 00 00 00 BE 01 00 00 00 E8 } // QR(x,1,5,9,13)
        $sigmax   = "expand 32-byte k" xor(0x01-0xff)
        $unmask   = { 83 F1 ?? 88 [2-3] 48 83 F8 10 75 }
        $localadr = { BF 08 08 08 08 [0-8] 66 C7 44 24 ?? 02 00 E8 ?? ?? ?? ?? BF 35 00 00 00 }
        $clamp    = { 80 [1-5] F8 [0-8] 83 E0 7F 83 C8 40 }
        $lockl    = { BF 01 00 00 7F E8 ?? ?? ?? ?? BF ?? ?? 00 00 }
        $deaffed  = { BA ED FF EA 0D }
        $plainxor = { 30 14 07 48 FF C0 EB F4 C3 }
        $mt64     = { 00 00 00 00 00 00 00 00 ?? ?? ?? ?? 00 00 00 00 01 00 00 00 00 00 00 00 ?? ?? ?? ?? 00 00 00 00 02 00 00 00 00 00 00 00 ?? ?? ?? ?? 00 00 00 00 03 00 00 00 00 00 00 00 ?? ?? ?? ?? 00 00 00 00 04 00 00 00 00 00 00 00 ?? ?? ?? ?? 00 00 00 00 05 00 00 00 00 00 00 00 ?? ?? ?? ?? 00 00 00 00 06 00 00 00 00 00 00 00 ?? ?? ?? ?? 00 00 00 00 07 00 00 00 00 00 00 00 ?? ?? ?? ?? 00 00 00 00 08 00 00 00 00 00 00 00 ?? ?? ?? ?? 00 00 00 00 09 00 00 00 00 00 00 00 ?? ?? ?? ?? 00 00 00 00 0A 00 00 00 00 00 00 00 ?? ?? ?? ?? 00 00 00 00 0B 00 00 00 00 00 00 00 }
    condition:
        uint32(0) == 0x464C457F and uint8(4) == 2 and uint16(16) == 2 and uint16(18) == 62
        and filesize < 3MB
        and ( ($qr1 and $qr2) or $sigmax or $unmask )
        and 1 of ($localadr, $clamp, $lockl, $deaffed, $plainxor, $mt64)
}
