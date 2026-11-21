import "pe"
import "hash"

rule WinLock_Pro_8_3
{
    meta:
        description = "Detect WinLock Pro 8.3 lol"
        author = "blade391off"
        date = "2026-09-11"
        category = "WinLock"
        threat_actor = "N/A"

    strings:
        $name1 = "WinLock" ascii wide nocase
        $name2 = "Crystal Office Systems" ascii wide nocase
        $name3 = "WinLock Installation" ascii wide nocase
        $name4 = "Setup/Uninstall" ascii wide nocase

        $path1 = "Program Files\\WinLock" ascii wide nocase
        $path2 = "ProgramData\\Crystal Office\\WL" ascii wide nocase
        $path3 = "Documents\\WinLock" ascii wide nocase
        $path4 = "Public\\Documents\\WinLock" ascii wide nocase

        $file1 = "winlock.exe" ascii wide nocase
        $file2 = "winlock.tmp" ascii wide nocase
        $file3 = "wlg.exe" ascii wide nocase
        $file4 = "uia.exe" ascii wide nocase
        $file5 = "winlockw.dat" ascii wide nocase

        $config1 = "winlocka.dat" ascii wide nocase
        $config2 = "winlocks.dat" ascii wide nocase
        $config3 = "wlg32.dat" ascii wide nocase
        $config4 = "games.wlp" ascii wide nocase
        $config5 = "internet.wlp" ascii wide nocase
        $config6 = "taskman.wlp" ascii wide nocase
        $config7 = "websites.wlp" ascii wide nocase
        $config8 = "browsers.wlp" ascii wide nocase

        $behavior1 = "netsh.exe" ascii wide nocase
        $behavior2 = "regedit" ascii wide nocase
        $behavior3 = "taskmgr" ascii wide nocase
        $behavior4 = "Image File Execution Options" ascii wide nocase
        $behavior5 = "SafeBoot" ascii wide nocase

        $version1 = "8.3" ascii wide
        $version2 = "8.3.0.0" ascii wide

    condition:
        (
            hash.sha256(0, filesize) == "34A27D49C795AA0E9908768B28FF529CB032EEB49A7B3AC63E508E0B41FECDC6" or
            hash.sha256(0, filesize) == "31F513CD9243DF5394FA2AF5206DAEC9524A0305BEDCCDCA10CEAA6A16977D9B" or
            hash.sha256(0, filesize) == "A19D1BF52EEE72C67322681ECE1F6A4B7DD5A2BEDCF3CCEDDDEE86484D959D0D" or
            hash.sha256(0, filesize) == "5777E6F05CB2ED178E834E7CA8F7589AABE4A92E4FB24FB69142E96F6D324663" or
            hash.sha256(0, filesize) == "C89C3B75C7AC891CBA6235000A78C16FE952F0599489D8C2028A7D7564BCB830" or
            hash.sha256(0, filesize) == "598EF2A95EB1A2CF0A0BBB4EDA1034DE8891A028B4536484FDB735FC798021B9" or
            hash.sha256(0, filesize) == "2783C77D65D67671F02C5F7F4370E3B885183D5810419300E115C90CD0672B69" or
            hash.sha256(0, filesize) == "28D316BD003B50E6E2C46D9D1E1BB2253B32C1B11673E058168E1C52EF579581" or
            hash.sha256(0, filesize) == "FFCBB73901ED60D69DA26A87CC96B3B0444FCC62E6219C4D5569371907EF861F"
        )

        or

        (
            pe.is_pe and
            pe.machine == pe.MACHINE_I386 and
            2 of ($name*) and
            1 of ($version*) and
            1 of ($path*) and
            1 of ($file*)
        )

        or

        (
            3 of ($config*) and
            1 of ($name1, $name2, $name3, $name4)
        )

        or

        (
            2 of ($behavior*) and
            2 of ($name*)
        )
}
