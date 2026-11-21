import "pe"

rule Loader_AMIDEWIN
{
    meta:
        author = "blade391off"
        description = "Detects Loader"
        date = "2026-08-20"
        version = "1.1"
        reference = "ANY.RUN e26f162e-b201-49a2-b534-cb73fab20bbd"
        sha256 = "506437635912ddbc0a8e50f37b2d90aca75beb90fbaa1b9aa43504c06411d38c"

    strings:
        $loader = "loader.exe" ascii wide nocase
        $amidewin = "AMIDEWINx64.EXE" ascii wide nocase
        $amidewin_cmd = "AMIDEWINx64.EXE /SU AUTO" ascii wide nocase
        $tmac_wifi = "tmac.exe -n Wi-Fi -r02 -re -s" ascii wide nocase
        $tmac_ethernet = "tmac.exe -n Ethernet -r -re -s" ascii wide nocase
        $oui_db = "oui.db" ascii wide nocase
        $amifldrv = "amifldrv64.sys" ascii wide nocase
        $curl = "curl.exe" ascii wide nocase
        $discord = "cdn.discordapp.com" ascii wide nocase
        $windows_temp = "C:\\Windows\\Temp\\" ascii wide nocase

    condition:
        pe.is_pe and
        (
            (
                3 of ($amidewin, $amidewin_cmd, $amifldrv, $oui_db) and
                1 of ($curl, $discord, $windows_temp)
            )
            or
            (
                $tmac_wifi and
                $tmac_ethernet and
                1 of ($amidewin, $amidewin_cmd, $amifldrv)
            )
            or
            (
                $amidewin_cmd and
                $amifldrv and
                $oui_db
            )
            or
            (
                $loader and
                2 of ($amidewin, $amifldrv, $oui_db, $discord)
            )
        )
}
