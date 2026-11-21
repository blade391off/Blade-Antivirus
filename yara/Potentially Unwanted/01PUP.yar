import "pe"

rule Target_Family_PUP_Heuristic
{
    meta:
        author = "blade391off"
        description = "Heuristic static detection of potentially unwanted software"
        date = "2026-08-16"
        threat_level = "medium"
        detection_type = "static_heuristic"

    strings:
        $indicator_1 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii wide nocase
        $indicator_2 = "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce" ascii wide nocase

        $indicator_3 = "EnableLUA" ascii wide nocase
        $indicator_4 = "ConsentPromptBehaviorAdmin" ascii wide nocase
        $indicator_5 = "PromptOnSecureDesktop" ascii wide nocase

        $indicator_6 = "\\AppData\\Local\\Temp\\" ascii wide nocase
        $indicator_7 = "\\AppData\\Roaming\\" ascii wide nocase
        $indicator_8 = "\\Temp\\" ascii wide nocase

        $indicator_9  = "advertisement" ascii wide nocase
        $indicator_10 = "adware" ascii wide nocase
        $indicator_11 = "popup" ascii wide nocase
        $indicator_12 = "sponsored" ascii wide nocase
        $indicator_13 = "offers" ascii wide nocase

        $api_1 = "RegCreateKeyExW" ascii
        $api_2 = "RegSetValueExW" ascii
        $api_3 = "LoadLibraryW" ascii
        $api_4 = "LoadLibraryExW" ascii

    condition:
        pe.is_pe
        and pe.number_of_signatures == 0
        and
        (
            // Persistence through the Run keys written by the binary itself,
            // plus adware wording. Requiring the wording keeps ordinary
            // software (which also uses the Run key) out of the results.
            (
                1 of ($indicator_1, $indicator_2)
                and
                1 of ($api_1, $api_2)
                and
                1 of ($indicator_9, $indicator_10, $indicator_11, $indicator_12, $indicator_13)
            )
            or
            (
                1 of ($indicator_3, $indicator_4, $indicator_5)
                and
                1 of ($api_1, $api_2)
                and
                1 of ($indicator_9, $indicator_10, $indicator_11, $indicator_12, $indicator_13)
            )
            or
            (
                2 of ($indicator_9, $indicator_10, $indicator_11, $indicator_12, $indicator_13)
                and
                1 of ($api_3, $api_4)
                and
                1 of ($indicator_6, $indicator_7, $indicator_8)
            )
        )
}
