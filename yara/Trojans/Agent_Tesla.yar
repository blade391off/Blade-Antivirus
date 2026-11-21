import "pe"

rule AgentTesla_200_Lines_Enterprise_Orchestrator
{
meta:
author = "blade391off"
description = "Detect AgentTesla"
date = "2026-08-08"
version = "1.0"
severity = "Critical"
sharing = "TLP"
mitre_tactics = "TA0006 Credential Access, TA0009 Collection, TA0011 Command and Control"

strings:
    $net_loader_0 = "v4.0.30319" ascii fullword
    $net_loader_1 = "<Module>" ascii fullword

    $guid_0 = "93c20d7e-06e9-44be-86bb-db9d60edc773" ascii wide
    $guid_1 = "29780517-84b2-4f61-b4f0-97c36a4da40c" ascii wide
    $guid_2 = "8ef7d781-a7c8-47fb-89c0-99436fc76037" ascii wide
    $guid_3 = "6a457497-6a58-45be-b97c-9b8e217034c2" ascii wide
    $guid_4 = "bfdf1c60-a292-4fc4-8d4e-b9bb7cb3fb2a" ascii wide
    $guid_5 = "b863aa9e-b14e-4f76-80f0-c529ff3ef9fa" ascii wide
    $guid_6 = "32b27b32-9a3b-48bb-a0e2-e1d93da4c11b" ascii wide

    $tgt_browser_0 = "signons.sqlite" ascii wide fullword
    $tgt_browser_1 = "Login Data" ascii wide fullword
    $tgt_browser_2 = "key3.db" ascii wide fullword
    $tgt_browser_3 = "key4.db" ascii wide fullword
    $tgt_browser_4 = "Cookies" ascii wide fullword
    $tgt_browser_5 = "Web Data" ascii wide fullword
    $tgt_browser_6 = "History" ascii wide fullword

    $tgt_ftp_0 = "wcx_ftp.ini" ascii wide fullword
    $tgt_ftp_1 = "CoreFTP" ascii wide fullword
    $tgt_ftp_2 = "FileZilla" ascii wide fullword
    $tgt_ftp_3 = "recentservers.xml" ascii wide fullword
    $tgt_ftp_4 = "sitemanager.xml" ascii wide fullword
    $tgt_ftp_5 = "FlashFXP" ascii wide fullword
    $tgt_ftp_6 = "SmartFTP" ascii wide fullword

    $tgt_mail_0 = "Account.stg" ascii wide fullword
    $tgt_mail_1 = "Outlook" ascii wide fullword
    $tgt_mail_2 = "Thunderbird" ascii wide fullword
    $tgt_mail_3 = "Postbox" ascii wide fullword
    $tgt_mail_4 = "Foxmail" ascii wide fullword
    $tgt_mail_5 = "Opera Mail" ascii wide fullword
    $tgt_mail_6 = "Qualcomm" ascii wide fullword

    $tgt_vpn_0 = "NordVpn.exe" ascii wide fullword
    $tgt_vpn_1 = "user.config" ascii wide fullword
    $tgt_vpn_2 = "OpenVPN" ascii wide fullword
    $tgt_vpn_3 = "ProtonVPN" ascii wide fullword
    $tgt_vpn_4 = "Private Internet Access" ascii wide fullword

    $tgt_sys_0 = "Trident/7.0" ascii wide fullword
    $tgt_sys_1 = "Account.rec" ascii wide fullword
    $tgt_sys_2 = "Software\\Valve\\Steam" ascii wide
    $tgt_sys_3 = "Discord" ascii wide

    $meth_steal_0 = "GetClipboardData" ascii wide fullword
    $meth_steal_1 = "GetSavedPasswords" ascii wide
    $meth_steal_2 = "GetSavedCookies" ascii wide
    $meth_steal_3 = "UploadValues" ascii wide fullword
    $meth_steal_4 = "DecryptPassword" ascii wide
    $meth_steal_5 = "GetMozilla" ascii wide
    $meth_steal_6 = "GetChromium" ascii wide
    $meth_steal_7 = "CaptureScreen" ascii wide
    $meth_steal_8 = "GetCyberFox" ascii wide
    $meth_steal_9 = "GetIceDragon" ascii wide

    $meth_net_0 = "DownloadString" ascii wide fullword
    $meth_net_1 = "UploadData" ascii wide fullword
    $net_smtp_0 = "SmtpClient" ascii wide fullword
    $meth_net_3 = "MailMessage" ascii wide fullword
    $meth_net_4 = "Attachment" ascii wide fullword
    $meth_net_5 = "CredentialCache" ascii wide fullword
    $meth_net_6 = "WebClient" ascii wide fullword

    $api_stealth_0 = "NtProtectVirtualMemory" ascii fullword
    $api_stealth_1 = "GetDelegateForFunctionPointer" ascii fullword
    $api_stealth_2 = "DynamicInvoke" ascii fullword
    $api_stealth_3 = "BlockInput" ascii fullword
    $api_stealth_4 = "Marshal" ascii fullword
    $api_stealth_5 = "BitConverter" ascii fullword

    $reg_zone = "SEE_MASK_NOZONECHECKS" ascii wide fullword

    $folder_0 = "\\Mozilla\\Firefox\\" ascii wide
    $folder_1 = "\\Google\\Chrome\\User Data\\" ascii wide
    $folder_2 = "\\Opera Software\\Opera Stable\\" ascii wide
    $folder_3 = "\\Thunderbird\\Profiles\\" ascii wide
    $folder_4 = "\\Comodo\\IceDragon\\" ascii wide

    $hex_xor_decrypt = { 8A 04 [0-2] 32 04 [0-2] 88 04 [0-2] 40 3B [0-2] 7C F0 }

condition:
    uint16(0) == 0x5A4D
    and filesize > 30KB
    and filesize < 8MB
    and (
        pe.imports("mscoree.dll", "_CorExeMain")
        or pe.imports("mscoree.dll", "_CorDllMain")
    )
    and ($net_loader_0 and $net_loader_1)
    and pe.number_of_signatures == 0
    and pe.number_of_sections >= 2
    and pe.number_of_sections <= 7
    and (
        for any i in (0..pe.number_of_sections - 1) : (
            pe.sections[i].characteristics & 0x00000020
            and pe.sections[i].virtual_size > 0
        )
    )
    and (
        any of ($guid_*)
        or (5 of ($tgt_browser_*) and 3 of ($folder_*))
        or (4 of ($tgt_ftp_*))
        or (4 of ($tgt_mail_*))
        or (3 of ($tgt_vpn_*))
        or (
            $reg_zone
            and (2 of ($tgt_browser_*) or 2 of ($tgt_ftp_*))
            and 1 of ($api_stealth_*)
        )
        or (
            3 of ($tgt_sys_*)
            and ($net_smtp_0 or 2 of ($meth_net_*))
        )
        or (
            4 of ($meth_steal_*)
            and 3 of ($api_stealth_*)
        )
        or (
            $hex_xor_decrypt
            and (2 of ($tgt_browser_*) or 2 of ($tgt_ftp_*))
        )
    )

}

rule AgentTesla_Installation_Artifacts
{
meta:
author = "blade391off"
description = "Detects installation mechanisms AgentTesla"
date = "2026-08-08"
version = "1.1"
severity = "High"
sharing = "TLP"

strings:
    $net_env_0 = "v4.0.30319" ascii fullword
    $net_env_1 = "<Module>" ascii fullword

    $drop_0 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii wide
    $drop_1 = "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce" ascii wide
    $drop_2 = "tmp" ascii wide fullword
    $drop_3 = "exe" ascii wide fullword

    $proc_0 = "GetProcessesByName" ascii wide fullword
    $proc_1 = "Kill" ascii wide fullword
    $proc_2 = "GetCurrentProcess" ascii wide fullword

    $sec_0 = "CheckRemoteDebuggerPresent" ascii wide fullword
    $sec_1 = "IsDebuggerPresent" ascii wide fullword
    $sec_2 = "add_Shutdown" ascii wide fullword

    $web_0 = "smtp" ascii wide nocase
    $web_1 = "pop3" ascii wide nocase
    $web_2 = "ftp" ascii wide nocase
    $web_3 = "http" ascii wide nocase

condition:
    uint16(0) == 0x5A4D
    and filesize > 20KB
    and filesize < 5MB
    and (
        pe.imports("mscoree.dll", "_CorExeMain")
        or pe.imports("mscoree.dll", "_CorDllMain")
    )
    and all of ($net_env_*)
    and pe.number_of_signatures == 0
    and (
        (2 of ($drop_*) and 2 of ($proc_*) and 1 of ($sec_*))
        or (3 of ($proc_*) and 2 of ($web_*))
        or (2 of ($sec_*) and 2 of ($web_*))
    )

}
