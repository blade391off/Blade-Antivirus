import "pe"

rule Win_Malware_RedLine_Production {
    meta:
        rule_id      = "REDLINE-PROD-001"
        version      = "1.0"
        author       = "blade391off"
        description  = "Production-ready rule for RedLine Stealer targeting .NET artifacts with high confidence"
        confidence   = "high"
        severity     = "critical"
        family       = "RedLine"
        category     = "Malware"
        malware_type = "Infostealer"
        tlp          = "WHITE"
        date         = "2026-08-04"

    strings:
        $core_wallets       = "AllWallets" ascii wide
        $core_message_token = "MessageToken" ascii wide
        $core_user_key      = "User_Key" ascii wide
        $core_cmd_update    = "CommandLineUpdate" ascii wide

        $browser_login_data    = "Login Data" ascii wide
        $browser_local_state   = "Local State" ascii wide
        $browser_cookies_sqlite = "cookies.sqlite" ascii wide

        $network_auth_check     = "AuthorizationCheck" ascii wide
        $network_remote_endpoint = "IRemoteEndpoint" ascii wide

        $config_encrypted_key = "encrypted_key" ascii wide

        $system_hardware_token = "hardwareToken" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        pe.is_pe and
        pe.imports("mscoree.dll", "_CorExeMain") and
        filesize > 20KB and filesize < 15MB and
        (
            (2 of ($core_*)) and 
            (
                (2 of ($browser_*)) or 
                (1 of ($browser_*) and 1 of ($network_*)) or
                (1 of ($network_*) and $config_encrypted_key) or
                ($system_hardware_token and 1 of ($browser_*))
            )
        )
}
