/*
   steamlure WebView2 fake Steam client family (CORD t20261028-2, deep unit).
   Candidate rules; test results in TEST.md. Static markers only.
*/
import "pe"

rule steamlure_wv2_bridge_app
{
    meta:
        description = "Fake Steam login window (x64, WebView2) that loads a remote phishing page and exposes a window.steamm JSON bridge (http.request, fs.readText/writeText, shell.open, win.*)"
        family = "steamlure WebView2 lure"
        reference = "https://0xcaecffd.github.io/cord-reports/reports/2026-10-steam-lure/"
        author = "CORD"
        date = "2026-10-29"
        samples = "10 of 10 g2/g3 builds (2026-09-17 .. 2026-10-19)"
    strings:
        // document-created bridge script (UTF-16 literal in .rdata)
        $b1 = "window.steamm" wide
        $b2 = "__steammHooked" wide
        $b3 = "__steamm_ov" wide
        $b4 = "http.request" wide
        // browser switches that turn off SmartScreen / Safe Browsing inside WebView2
        $a1 = "WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS" wide
        $a2 = "msSmartScreenProtection,msEnhancedSecurityMode,msSafeLinksValidation" wide
        $a3 = "--disable-client-side-phishing-detection" wide
        // JSON-RPC method names compared as 64-bit immediates in the dispatcher
        $m1 = "win.drag"
        $m2 = "win.clos"
        $m3 = "win.resi"
        $m4 = "http.req"
        $m5 = "fs.write"
        $m6 = "fs.readT"
        $e1 = "only http(s) allowed"
        $e2 = "unknown method: "
        $w1 = "SteamWindow" wide
        $w2 = "Steam/1.0" wide
    condition:
        uint16(0) == 0x5A4D and pe.is_64bit() and filesize < 3MB and
        (
            (2 of ($b*) and 1 of ($a*)) or
            (4 of ($m*) and 1 of ($e*)) or
            ($a1 and $a2 and $w1 and $w2)
        )
}

rule steamlure_wv2_c2_url
{
    meta:
        description = "WebView2 lure build that embeds a numeric f1shh.at subdomain /client URL (UTF-16)"
        author = "CORD"
        date = "2026-10-29"
    strings:
        $u = /h\x00t\x00t\x00p\x00s\x00:\x00\/\x00\/\x00([0-9]\x00){9,10}\.\x00f\x001\x00s\x00h\x00h\x00\.\x00a\x00t\x00\/\x00c\x00l\x00i\x00/
    condition:
        uint16(0) == 0x5A4D and $u
}

rule steamlure_wv2_steamui_hijacker
{
    meta:
        description = "SteamUI variant (3d2b12f8): replaces steam.exe, re-points steam:// handler, App Paths and shortcuts, serves a local Steam login UI over WebView2 to a relay kit"
        family = "steamlure WebView2 lure (SteamUI hijacker)"
        reference = "https://0xcaecffd.github.io/cord-reports/reports/2026-10-steam-lure/"
        author = "CORD"
        date = "2026-10-29"
    strings:
        $s1 = "steam.orig.exe" wide
        $s2 = "steam.live.exe" wide
        $s3 = "%s\\SteamUI\\steam.exe" wide
        $s4 = "https://steamui.local/*" wide
        $s5 = "Steam Client Service" wide
        $s6 = "Software\\Classes\\steam\\shell\\open\\command" wide
        $s7 = "__steamUiMounted" wide
        $s8 = "SteamClientWnd" wide
        $j1 = "steam-inject-root"
        $j2 = "parseTokenSecret"
        $j3 = "'DyNaM1c'"
        $j4 = "checkConfirmations"
    condition:
        uint16(0) == 0x5A4D and filesize < 5MB and
        (5 of ($s*) or (3 of ($j*) and 2 of ($s*)))
}
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
