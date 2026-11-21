import "pe"

rule Win_Malware_Lumma_Deep_Classification {
    meta:
        rule_id      = "LUMMA-DEEP-001"
        version      = "1.0"
        author       = "blade391off"
        description  = "Deep classification engine for Lumma Stealer enforcing strict multi-stage validation"
        confidence   = "high"
        severity     = "critical"
        family       = "Lumma"
        category     = "Malware"
        malware_type = "Infostealer"
        tlp          = "WHITE"
        date         = "2026-08-04"

    strings:
        $core_param_1 = "con=" ascii wide
        $core_param_2 = "tid=" ascii wide
        $core_param_3 = "&act=" ascii wide

        $browser_chromium = "Login Data" ascii wide
        $browser_firefox  = "profiles.ini" ascii wide
        $browser_local    = "Local State" ascii wide

        $network_boundary = "----WebKitFormBoundary" ascii wide
        $network_disp     = "Content-Disposition: form-data; name=" ascii wide
        $network_ct       = "Content-Type: multipart/form-data;" ascii wide

        $config_c2    = "c2_list" ascii wide
        $config_build = "build_id" ascii wide

        $system_env_1 = "GetNativeSystemInfo" ascii wide
        $system_env_2 = "CryptStringToBinaryA" ascii wide

        $crypto_metamask = "nkbihfbeogaeaoehlefnkodbefgpgknn" ascii wide
        $crypto_phantom  = "bfna6nanaeoigbphlanat6at6bba" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        pe.is_pe and
        not pe.imports("mscoree.dll", "_CorExeMain") and
        filesize > 50KB and filesize < 5MB and

        3 of ($core_*) and

        2 of ($browser_*) and

        2 of ($network_*) and

        2 of ($config_*) and

        2 of ($system_env_*) and

        1 of ($crypto_*)
}
