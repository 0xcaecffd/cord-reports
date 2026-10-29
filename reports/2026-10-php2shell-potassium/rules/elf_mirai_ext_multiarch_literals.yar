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
