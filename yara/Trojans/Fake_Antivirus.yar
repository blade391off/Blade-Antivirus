import "pe"

rule Fake_Antivirus_Generic_Optimized {
    meta:
        author = "blade391off_optimized"
        description = "Optimized production-ready rule for Fake Antivirus (Scareware) detecting without performance loss"
        date = "2026-08-11"
        version = "1.1"
        severity = "High"

    strings:
        $alert_0 = "Hard drive is corrupted" ascii wide fullword
        $alert_1 = "Infections found" ascii wide fullword
        $alert_2 = "Spyware detected" ascii wide fullword
        $alert_3 = "Critical system leak" ascii wide fullword
        $alert_4 = "System damage" ascii wide fullword
        $alert_5 = "Threats detected" ascii wide fullword

        $pay_0 = "Activate license" ascii wide fullword
        $pay_1 = "Buy full version" ascii wide fullword
        $pay_2 = "Register your copy" ascii wide fullword
        $pay_3 = "Enter activation key" ascii wide fullword
        $pay_4 = "Purchase protection" ascii wide fullword

        $ui_0 = "Scanning system" ascii wide fullword
        $ui_1 = "Scan results" ascii wide fullword
        $ui_2 = "Antivirus Protection" ascii wide fullword
        $ui_3 = "PC Health" ascii wide fullword

        $reg_path = "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" ascii wide
        $lock_0 = "DisableTaskMgr" ascii wide fullword
        $lock_1 = "DisableRegistryTools" ascii wide fullword

    condition:
        uint16(0) == 0x5A4D and
        filesize < 10MB and
        not pe.is_dll() and
        pe.number_of_signatures == 0 and
        (
            (3 of ($alert_*) and 2 of ($pay_*)) or
            (2 of ($alert_*) and 2 of ($ui_*) and 1 of ($pay_*)) or
            (
                $reg_path and
                1 of ($lock_*) and
                (2 of ($alert_*) or 1 of ($pay_*))
            )
        )
}
