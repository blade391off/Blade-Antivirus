import "pe"
import "hash"

rule Detect_Default_Wiper
{
    meta:
        author = "blade391off"
        description = "Detect Default Wiper (SameCoin / WIRTE)"
        version = "2.2"

    strings:
        $s_chrome   = "Google\\Chrome\\User Data\\Default\\Code Cache\\js" ascii wide
        $s_edge     = "Microsoft\\Edge\\User Data\\Default\\Service Worker\\CacheStorage" ascii wide
        $s_firefox  = "Mozilla\\Firefox\\Profiles" ascii wide
        $s_skype    = "Skype for Desktop\\Partitions" ascii wide
        $s_msocache = "MSOCache\\All Users" ascii wide
        $s_adobe    = "Adobe\\AcroCef\\DC\\Acrobat\\Cache" ascii wide
        $s_threat   = "HAMAS" ascii wide nocase

    condition:
        uint16(0) == 0x5A4D and 
        filesize > 40KB and 
        filesize < 15MB and
        (
            hash.md5(0, filesize) == "a8b54533c6a84888d2db8305e5b42153" or
            hash.md5(0, filesize) == "cbca0a9b1dc35ea2549bceb44a2e9a11" or
            hash.md5(0, filesize) == "c361872a1ea03e69a0ac453d29b975aa" or
            hash.md5(0, filesize) == "c297bfa4fd4e883d010c995d6eaf901f" or
            hash.md5(0, filesize) == "3da8fa7e04bb758d67ff52efacbb5000" or
            hash.md5(0, filesize) == "57bb1e276bd96092587230eaa40a35e3" or
            hash.md5(0, filesize) == "9ceea7205d7d081bccd972fde066e619" or
            hash.md5(0, filesize) == "a9705dd1b64664307466504ce2244b2d" or

            hash.sha1(0, filesize) == "86c1fb08637325c2b3468ccabf929572c39c04ca" or

            hash.sha256(0, filesize) == "e6d2f43622e3ecdce80939eec9fffb47e6eb7fc0b9aa036e9e4e07d7360f2b89" or
            hash.sha256(0, filesize) == "d5447bc4a28339634d09f5e0abf3e70fa8e97b2345f214088b25aa61f3224e0b" or
            hash.sha256(0, filesize) == "d9f091345ab33a624073fb58c30867f2e100a7fed3e4359c64f8e71aa102b045" or
            hash.sha256(0, filesize) == "bc7ef86f2f2886f14b808f04f7623a063e4ad02d52f7a089fddec8e5cc91e004" or
            hash.sha256(0, filesize) == "cdfc4db9191ede52ada47a7739213bf7339cd35d09866b7441f7207cb714e2ad" or
            hash.sha256(0, filesize) == "0e4b0da5bb6d980cdadbe00f725f469669619d14170ef2db1c90e43058dc8d01" or
            hash.sha256(0, filesize) == "1288484c561165a932e7e2a2bbec14f5c9e32c87dfd765179b3b188e8217b87c" or
            hash.sha256(0, filesize) == "7022e5de1a71d130f1e9016c5d4022bb4b7ae17f1e2e1af34687a14a901f3fdd" or

            (
                pe.machine == pe.MACHINE_I386 and
                pe.subsystem == pe.SUBSYSTEM_WINDOWS_CUI and
                pe.linker_version.major == 14 and
                pe.linker_version.minor == 38 and
                pe.timestamp >= 1704067200 and pe.timestamp <= 1711929600 and
                3 of ($s_*)
            )
        )
}
