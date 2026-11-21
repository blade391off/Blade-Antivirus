import "pe"

rule NJrat_Trojan {
    meta:
        author = "blade391off"
        description = "Detects NJrat (Bladabindi) Remote Access Trojan core payloads and variants"
        date = "2026-08-08"
        version = "1.0"
        severity = "Critical"

    strings:
        $nj_0 = "[VaporRAT]" ascii wide
        $nj_1 = "netsh advfirewall set allprofiles state off" ascii wide nocase
        $nj_2 = /cmd\.exe\s+\/[ck]\s+ping\s+127\.0\.0\.1\s+[^&]+&\s*del/ ascii wide nocase

        $del_0 = "[id]" ascii wide fullword
        $del_1 = "[gl]" ascii wide fullword
        $del_2 = "[vn]" ascii wide fullword
        $del_3 = "SEE_MASK_NOZONECHECKS" ascii wide

        $hex_net_magic = { 3A 00 27 00 3A 00 27 00 3A }

    condition:
        uint16(0) == 0x5A4D and filesize < 5MB and
        (
            pe.imports("mscoree.dll", "_CorExeMain") or
            pe.imports("mscoree.dll", "_CorDllMain")
        ) and
        (
            any of ($nj_*) or
            3 of ($del_*) or
            ($hex_net_magic and 2 of ($del_*))
        )
}
