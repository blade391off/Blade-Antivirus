import "pe"

rule Win_Malware_Raccoon_Triage {
    meta:
        description = "Fast triage rule for Raccoon Stealer requiring core artifact presence"
        author = "blade391off"
        version = "1.0"

    strings:
        $core_snippets = "libsnippets" ascii wide
        $core_nss_init = "nss_Init" ascii wide

        $browser_chrome = "--- Chrome ---" ascii wide
        $browser_fox = "--- Firefox ---" ascii wide

        $network_bot = "bot_id=" ascii wide
        $network_ver = "config_version" ascii wide

        $log_sysinfo = "System Info.txt" ascii wide
        $log_screen = "Screenshot.jpeg" ascii wide

    condition:
        uint16(0) == 0x5A4D and pe.is_pe and filesize > 20KB and filesize < 5MB and 
        1 of ($core_*) and (
            1 of ($browser_*) or
            1 of ($network_*) or
            1 of ($log_*)
        )
}
