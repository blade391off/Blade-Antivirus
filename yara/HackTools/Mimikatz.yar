rule Detect_Mimikatz {
    meta:
        author = "blade391off"
        description = "Detect Mimikatz"
        malware_family = "Mimikatz"
        severity = "Critical"
        reference = "Internal Threat Intelligence / Benjamin Delpy Mimikatz Research"
        version = "1.1"
        detection_type = "Both"
    strings:
        $msv_credential_search_x64 = { 4c 8b [1-5] 4c 3b [1-3] 75 [1-3] 49 8b [1-5] 49 39 [1-3] 75 [1-3] 41 8b [1-3] 4d 85 [1-3] 74 [1-3] 49 8b } private
        $wdigest_extraction_x64 = { 48 8b [1-5] 48 8b [1-5] 4c 8d [1-5] 4c 8b [1-5] e8 [1-4] 48 85 c0 74 [1-3] 48 8b [1-5] 48 89 } private
        $tspkg_helper_x64 = { 48 83 ec 20 4c 8b [1-5] 4c 3b [1-3] 75 [1-3] 48 8b [1-5] 45 33 c9 4c 8d [1-5] 48 8b } private
        $bcrypt_key_deriv_x64 = { 4c 8b [1-5] 48 8d [1-5] e8 [1-4] 48 85 c0 74 [1-3] 45 33 c9 4c 8d [1-5] 48 8b [1-5] e8 [1-4] 48 85 c0 } private
        $kuhl_sekurlsa_01 = "kuhl_m_sekurlsa_init" ascii private
        $kuhl_sekurlsa_02 = "kuhl_m_sekurlsa_clean" ascii private
        $kuhl_msv_01 = "kuhl_m_sekurlsa_msv_keys" ascii private
        $kuhl_wdigest_01 = "kuhl_m_sekurlsa_wdigest_init" ascii private
        $kuhl_dpapi_01 = "kuhl_m_sekurlsa_dpapi_masterkeys" ascii private
    condition:
        (uint16(0) == 0x5a4d or not uint16(0)) and
        filesize < 5MB and
        (
            (all of ($kuhl_sekurlsa_*) and 2 of ($kuhl_*)) or
            ($msv_credential_search_x64 and $wdigest_extraction_x64 and $bcrypt_key_deriv_x64) or
            (4 of ($kuhl_*) and 1 of ($msv_*, $wdigest_*, $tspkg_*)) or
            ($msv_credential_search_x64 and 2 of ($kuhl_*)) or
            ($wdigest_extraction_x64 and $tspkg_helper_x64 and $bcrypt_key_deriv_x64)
        )
}
