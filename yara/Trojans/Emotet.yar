import "pe"

rule EMOTET_Trojan {
    meta:
        author = "blade391off"
        description = "Detects Emotet core payloads and custom loaders"
        date = "2026-08-08"
        version = "1.0"
        severity = "Critical"

    strings:
        $hex_emotet_xor_loop = { 8A 14 07 32 14 0E 88 14 07 40 3B C3 7C F0 }
        $hex_api_hash_calc = { 33 C0 0F B6 1C 0A 03 F3 C1 CE 0D 41 84 DB 75 F1 }
        $hex_syscall_resolve = { 4C 8B D1 B8 ?? ?? ?? ?? 0F 05 }

        $str_loader_alloc = "VirtualAlloc" ascii
        $str_loader_protect = "VirtualProtect" ascii
        $str_loader_load = "LoadLibrary" ascii
        $str_loader_proc = "GetProcAddress" ascii

    condition:
        uint16(0) == 0x5A4D and
        filesize < 3MB and
        (
            ($hex_emotet_xor_loop and $hex_api_hash_calc) or
            ($hex_syscall_resolve and $hex_api_hash_calc) or
            (
                pe.is_dll() and
                pe.number_of_exports > 0 and
                pe.number_of_exports < 4 and
                $hex_api_hash_calc and
                3 of ($str_loader_*)
            )
        )
}

rule EMOTET_Dropper {
    meta:
        author = "blade391off"
        description = "Detects Emotet dropper patterns including malicious macros, scripts, and initial delivery payloads"
        date = "2026-08-08"
        version = "1.0"
        severity = "Critical"

    strings:
        $wmi_0 = "winmgmts" ascii wide nocase
        $wmi_1 = "Win32_Process" ascii wide nocase
        $wmi_2 = "Win32_ProcessStartup" ascii wide nocase

        $enc_0 = "Base64String" ascii wide nocase
        $enc_1 = "FromBase64" ascii wide nocase
        $enc_2 = "XOR" ascii wide nocase

        $cmd_0 = "powershell" ascii wide nocase
        $cmd_1 = "cmd.exe /c" ascii wide nocase
        $cmd_2 = "mshta" ascii wide nocase
        $cmd_3 = "rundll32" ascii wide nocase
        $cmd_4 = "cscript" ascii wide nocase
        $cmd_5 = "wscript" ascii wide nocase

        $net_url_regex = /https?:\/\/[^\s"']+\.[a-z]{2,6}\/[a-zA-Z0-9_\-\.]+\.(exe|dll|ocx|dat)/ ascii nocase

    condition:
        (
            (uint16(0) == 0xCFD0 or
             uint32(0) == 0x464F4A1A or
             uint32(0) == 0x504B0304) and
            (
                (2 of ($wmi_*) and 1 of ($cmd_*)) or
                (1 of ($wmi_*) and 2 of ($enc_*) and 1 of ($cmd_*)) or
                (1 of ($cmd_*) and $net_url_regex)
            )
        ) or
        (
            uint16(0) == 0x5A4D and
            filesize < 5MB and
            not pe.is_dll() and
            (
                (3 of ($cmd_*) and $net_url_regex) or
                (2 of ($cmd_*) and 2 of ($enc_*))
            )
        )
}
