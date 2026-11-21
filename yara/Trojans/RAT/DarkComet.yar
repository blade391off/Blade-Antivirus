import "pe"

rule DarkComet_Trojan {
    meta:
        author = "blade391off"
        description = "Production-grade rule for DarkComet RAT with strict structural validation"
        date = "2026-08-08"
        version = "1.0"
        severity = "Critical"
        sharing = "TLP:CLEAR"

    strings:
        $str_key_0 = "#KCMDDC" ascii wide fullword
        $str_key_1 = "#KCMDDI" ascii wide fullword
        $str_mutex = "DC_MUTEX_" ascii wide

        $rat_ui_0 = "DARKCOMET" ascii wide nocase
        $rat_ui_4 = "dcom.server" ascii wide nocase

        $delphi_0 = "ADVAPI32.DLL" ascii fullword
        $delphi_1 = "safecall" ascii fullword

        $hex_rc4_init = { 31 C0 89 [0-4] 8A [0-4] 88 [0-4] 40 3D 00 01 00 00 7C }
        $hex_key_resolve = { 8A [0-4] 30 [0-4] 40 3B [0-4] 7C }

    condition:
        uint16(0) == 0x5A4D and
        filesize < 4MB and
        not pe.is_dll() and
        all of ($delphi_*) and
        (
            (any of ($str_key_*) and 1 of ($hex_*)) or
            ($str_mutex and 1 of ($rat_ui_*) and 1 of ($hex_*)) or
            (all of ($hex_*) and 1 of ($rat_ui_*))
        )
}
