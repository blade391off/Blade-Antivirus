rule Deep_Petya_Family {
    meta:
        author = "blade391off"
        description = "Deep detection rule for Petya family using precise binary payloads, MBR structures, and cryptographic anomalies"
        threat_level = "Critical"
        date = "2026-08-11"

    strings:
        $mbr_sector_1 = { 8E D8 8E D0 BC 00 7C 89 E6 } 
        $mbr_sector_2 = { FA B8 00 00 8E D0 BC 00 7C FB } 
        $mbr_sector_3 = { B8 00 02 B8 01 02 BB 00 80 B9 01 00 CD 13 }
        $mbr_sector_4 = { B4 02 B0 22 ?? 00 ?? 02 ?? 00 ?? 80 }
        
        $petya_kernel_1 = { 66 63 64 73 6B 2E 65 78 65 } 
        $petya_kernel_2 = { 45 4E 54 45 52 20 4B 45 59 }
        
        $salsa20_matrix_1 = "expand 32-byte k" ascii fullword
        $salsa20_matrix_2 = "expand 16-byte k" ascii fullword

        $psexec_command_1 = { 2D 61 63 63 65 70 74 65 75 6C 61 } 
        $psexec_command_2 = { 2D 64 20 2D 63 20 2D 66 }
        
        $token_privs_1 = { 53 65 44 65 62 75 67 50 72 69 76 69 6C 65 67 65 } 
        $token_privs_2 = { 53 65 54 61 6B 65 4F 77 6E 65 72 73 68 69 70 50 72 69 76 69 6C 65 67 65 }
        $token_privs_3 = { 53 65 42 61 63 6B 75 70 50 72 69 76 69 6C 65 67 65 }
        $token_privs_4 = { 53 65 52 65 73 74 6F 72 65 50 72 69 76 69 6C 65 67 65 }

        $wevtutil_wipe_1 = "wevtutil cl Setup" ascii wide
        $wevtutil_wipe_2 = "wevtutil cl System" ascii wide
        $wevtutil_wipe_3 = "wevtutil cl Security" ascii wide
        $wevtutil_wipe_4 = "wevtutil cl Application" ascii wide
        
        $shutdown_force_1 = "shutdown.exe /r /f" ascii wide
        $shutdown_force_2 = "shutdown /r /t 0" ascii wide

        $wmi_lateral_1 = "wmic /node:" ascii wide
        $wmi_lateral_2 = "process call create" ascii wide

        $dhcp_exploit_1 = { 4A 45 54 5F 62 61 73 65 6E 61 6D 65 }
        $dhcp_exploit_2 = { 44 68 63 70 47 65 74 41 6C 6C 4F 70 74 69 6F 6E 44 65 66 69 6E 69 74 69 6F 6E 73 }

        $petya_perfc_dat = /\\C\$\\Windows\\perfc\.dat/ ascii wide
        $ipc_share_2 = "\\\\*\\admin$" ascii wide

    condition:
        uint16(0) == 0x5A4D and filesize < 15MB and (
            $petya_perfc_dat or
            ( 2 of ($mbr_sector_*) and any of ($salsa20_matrix_*) ) or
            ( any of ($petya_kernel_*) and any of ($salsa20_matrix_*) ) or
            ( all of ($dhcp_exploit_*) and any of ($token_privs_*) ) or
            ( any of ($petya_kernel_*) and 2 of ($token_privs_*) and 2 of ($wevtutil_wipe_*) and any of ($shutdown_force_*) ) or
            ( any of ($petya_kernel_*) and any of ($psexec_command_*) and $ipc_share_2 and any of ($wmi_lateral_*) ) or
            ( all of ($dhcp_exploit_*) and any of ($psexec_command_*) and any of ($wmi_lateral_*) )
        )
}
