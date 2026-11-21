import "pe"

rule Win_Malware_Raccoon_Deep_Refined {
    meta:
        description = "Deep classification rule for Raccoon Stealer"
        author = "blade391off"
        version = "1.0"

    strings:
        $core_snippets = "libsnippets" ascii wide
        $core_nss_init = "nss_Init" ascii wide

        $browser_login = "Login Data" ascii wide
        $browser_state = "Local State" ascii wide

        $firefox_key = "key4.db" ascii wide
        $firefox_logins = "logins.json" ascii wide

        $network_bot = "bot_id=" ascii wide
        $network_ver = "config_version" ascii wide

        $crypto_exodus = "Exodus" ascii wide
        $crypto_metamask = "MetaMask" ascii wide

        $log_chrome = "--- Chrome ---" ascii wide
        $log_fox = "--- Firefox ---" ascii wide

        $system_info = "System Info.txt" ascii wide
        $system_screen = "Screenshot.jpeg" ascii wide

    condition:
        uint16(0) == 0x5A4D and pe.is_pe and filesize > 20KB and filesize < 5MB and 
        all of ($core_*) and 
        (all of ($browser_*) or all of ($firefox_*)) and 
        (all of ($network_*) or all of ($crypto_*)) and 
        (all of ($log_*) or all of ($system_*))
}
