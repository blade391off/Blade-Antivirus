import "pe"

rule SmokeLoader
{
    meta:
        author = "blade391off"
        description = "Detection rule for Smoke Loader"
        reference = "https://any.run/malware-trends/smoke/"
        date = "2026-08-23"

    strings:
        $appdata = "\\AppData\\Roaming\\Microsoft\\" ascii wide
        $run_key = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii wide

        $api1 = "RegOpenKeyExA" ascii
        $api2 = "RegSetValueExA" ascii
        $api3 = "CreateProcessA" ascii
        $api4 = "VirtualAlloc" ascii
        $api5 = "WriteProcessMemory" ascii
        $api6 = "GetProcAddress" ascii
        $api7 = "LoadLibraryA" ascii

        $domain1 = "gcl-gb.biz" ascii wide
        $domain2 = "wfsdragon.ru" ascii wide
        $domain3 = "directorycart.com" ascii wide
        $domain4 = "iplogger.org" ascii wide

    condition:
        uint16(0) == 0x5A4D
        and pe.is_pe
        and
        (
            (
                pe.number_of_sections >= 2
                and for any i in (0 .. pe.number_of_sections - 1) : (
                    pe.sections[i].name == "UPX0"
                    or pe.sections[i].name == "UPX1"
                )
                and 2 of ($api*)
            )
            or
            (
                $run_key
                and $appdata
                and 3 of ($api1, $api2, $api3, $api4, $api5)
            )
            or
            (
                1 of ($domain*)
                and 2 of ($api*)
            )
        )
}
