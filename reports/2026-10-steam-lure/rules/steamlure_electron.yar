/*
   steamlure Electron fake Steam login app (steam-login-app, CORD t20261028-2 deep unit).
   Rules for the extracted package (app.asar, package.json, main.js, main.jsc)
   and one for the NSIS installer shell. Test results in TEST.md.
*/
import "pe"

rule steamlure_electron_package_json
{
    meta:
        description = "package.json of the fake Steam Electron app (name steam-login-app, author Valve Corporation, version 10.50.87.67); matches app.asar and the loose file"
        author = "CORD"
        date = "2026-10-29"
    strings:
        $n = "\"name\": \"steam-login-app\""
        $v = "\"version\": \"10.50.87.67\""
        $a = "\"author\": \"Valve Corporation\""
    condition:
        filesize < 20MB and $n and ($v or $a)
}

rule steamlure_electron_mainjs_obfuscated
{
    meta:
        description = "September plaintext main.js (obfuscator.io string array) of the fake Steam Electron app; also matches app.asar that carries it"
        author = "CORD"
        date = "2026-10-29"
    strings:
        $i1 = "TARGET_URLS"
        $i2 = "ANTI_DELETE"
        $i3 = "PROCESS_PROTECTION"
        $i4 = "WATCHER_SCRIPT"
        $i5 = "function mapLocaleToLang("
        $i6 = "function getAcceptLanguage("
        // obfuscator.io base64 (lowercase-first alphabet) of the TARGET_URLS entries
        $u1 = "Ahr0Chm6lY9UANjSBxD0z3bRlNnOB3aVmJeYmZiYmW"   // https://njrlmwtgpk.shop/2123223
        $u2 = "Ahr0Chm6lY9MywTLzMfRzs5ZAg9WlZmYntm1mJm"      // https://fakefake.shop/3253523
        $u3 = "D2LUzg93lL9Fyxv0B0nSAwnRzwqGFhWGzMfSC2u"      // window.__autoClicked || false
        $w = "require(watcherFile)"
        $o = /function _0x[0-9a-f]{4,6}\(\)\{const _0x[0-9a-f]{4,6}=\['/
    condition:
        filesize < 20MB and $o and 4 of ($i*) and ($w or 2 of ($u*))
}

rule steamlure_electron_mainjsc_bytecode
{
    meta:
        description = "October main.jsc (bytenode V8 code cache, Electron 25 / V8 11.4) of the fake Steam Electron app"
        author = "CORD"
        date = "2026-10-29"
    strings:
        $i1 = "TARGET_URLS"
        $i2 = "mapLocaleToLang"
        $i3 = "getAcceptLanguage"
        $i4 = "createWindow"
        $i5 = "ELECTRON_RUN_AS_NODE"
        $i6 = "--watcher"
        $u1 = "Ahr0Chm6lY9UANjSBxD0z3bRlNnOB3aVmJeYmZiYmW"
        $u2 = "Ahr0Chm6lY9MywTLzMfRzs5ZAg9WlZmYntm1mJm"
        $u3 = "https://pulse-keys.store/6887"
        $u4 = "https://fakefake.shop/3253523"
        $c1 = "_steamguardContainer_" wide
    condition:
        uint32(0) == 0xC0DE05DF and filesize < 2MB and 4 of ($i*) and (1 of ($u*) or $c1)
}

rule steamlure_electron_nsis_installer
{
    meta:
        description = "Unsigned NSIS installer posing as Steam with the builder's odd version string 10.50.8-7.67 (real Steam installers are Valve-signed)"
        author = "CORD"
        date = "2026-10-29"
    strings:
        $nsis = "NullsoftInst"
        $v1 = "10.50.8-7.67" wide
        $c = "Valve Corporation" wide
    condition:
        uint16(0) == 0x5A4D and pe.number_of_signatures == 0 and $nsis and $v1 and $c
}
