import "pe"

rule Default_Trojan
{
    meta:
        author = "blade391off"
        description = "Detects suspicious Windows PE files using process injection and destructive command indicators"
        date = "2026-08-30"
        version = "1.1"
        severity = "Critical"
        sharing = "TLP:CLEAR"

    strings:
        $str_name = "Default_Trojan" ascii wide

        $api_inj_0 = "NtCreateThreadEx" ascii
        $api_inj_1 = "VirtualAllocEx" ascii
        $api_inj_2 = "WriteProcessMemory" ascii
        $api_inj_3 = "QueueUserAPC" ascii
        $api_inj_4 = "RtlCreateUserThread" ascii

        $cmd_0 = "vssadmin.exe delete shadows" ascii wide
        $cmd_1 = "wevtutil.exe cl" ascii wide
        $cmd_2 = "bcdedit.exe /set {default} recoveryenabled No" ascii wide
        $cmd_3 = "netsh advfirewall set allprofiles state off" ascii wide

        $hex_xor = { 8A 04 0B 32 C2 88 04 0B 41 3B CA 7C F2 }
        $hex_rc4 = { 8A 14 01 02 D2 03 D0 8A 04 01 88 14 01 88 04 01 }
        $hex_egg = { 66 81 CA FF 0F 42 52 6A 02 58 CD 2E 3C 05 5A 74 EF B8 }
        $hex_api_resolve = { 64 8B 30 8B 76 0C 8B 76 1C 8B 6E 08 8B 7D 3C 8B 7C 3D 78 }
        $hex_heavens_gate = { 6A 33 E8 00 00 00 00 83 04 24 05 CB }
        $hex_unhooking = { 4C 8B D1 B8 18 00 00 00 0F 05 }

    condition:
        uint16(0) == 0x5A4D
        and filesize > 10KB
        and filesize < 10MB
        and not pe.is_dll()
        and
        (
            $str_name
            or
            (
                1 of ($hex_*)
                and
                (
                    3 of ($api_inj_*)
                    or
                    1 of ($cmd_*)
                )
            )
            or
            (
                $hex_unhooking
                and 2 of ($api_inj_*)
            )
            or
            (
                filesize < 2MB
                and pe.number_of_sections > 0
                and
                (
                    2 of ($api_inj_*)
                    or
                    1 of ($cmd_*)
                )
            )
        )
}
