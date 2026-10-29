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
