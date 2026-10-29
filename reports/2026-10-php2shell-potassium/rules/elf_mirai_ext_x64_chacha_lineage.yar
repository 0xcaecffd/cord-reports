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
