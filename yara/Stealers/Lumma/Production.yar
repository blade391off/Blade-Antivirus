import "pe"

rule Win_Malware_Lumma_Production {
    meta:
        rule_id      = "LUMMA-PROD-001"
        version      = "1.0"
        author       = "blade391off"
        description  = "Production-ready rule for Lumma Stealer based on subsystem intersection matrix"
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

        $config_c2        = "c2_list" ascii wide
        $config_build     = "build_id" ascii wide

        $crypto_metamask  = "nkbihfbeogaeaoehlefnkodbefgpgknn" ascii wide
        $crypto_phantom   = "bfna6nanaeoigbphlanat6at6bba" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        pe.is_pe and
        not pe.imports("mscoree.dll", "_CorExeMain") and
        filesize > 50KB and filesize < 5MB and
        (
            (2 of ($core_*)) and
            (
                (1 of ($browser_*) and 2 of ($network_*)) or
                (2 of ($network_*) and 1 of ($config_*)) or
                (1 of ($crypto_*) and 1 of ($browser_*)) or
                (1 of ($crypto_*) and 2 of ($network_*))
            )
        )
}
