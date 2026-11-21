import "pe"

rule Win_Malware_Lumma_Stealer_Triage
{
    meta:
        rule_id = "LUMMA-0001"
        description = "Triage and classification YARA rule targeting Lumma Stealer samples based on observed C2 structures and target browser telemetry"
        author = "blade391off"
        date = "2026-08-03"
        malware_family = "LummaStealer"
        threat_type = "Infostealer"
        severity = "High"
        reference = "Internal Research"

    strings:
        $c2_boundary_01 = "----WebKitFormBoundarylumma" ascii wide
        $c2_boundary_02 = "Content-Disposition: form-data; name=" ascii wide

        $c2_param_01 = "conext" ascii wide
        $c2_param_02 = "action=get_config" ascii wide
        $c2_param_03 = "pid=" ascii wide
        $c2_param_04 = "lid=" ascii wide
        $c2_param_05 = "tid=" ascii wide
        $c2_param_06 = "client_id=" ascii wide

        $ua_exact_01 = "TeslaBrowser/5.5" ascii wide

        $log_fmt_01 = "--- HARDWARE INFO ---" ascii wide
        $log_fmt_02 = "--- SCREENSHOT ---" ascii wide
        $log_fmt_03 = "--- PASSWORDS ---" ascii wide
        $log_fmt_04 = "--- COOKIES ---" ascii wide
        $log_fmt_05 = "--- WALLETS ---" ascii wide

        $ext_01 = "nkbihfbeogaeaoehlefnkodbefgpgknn" ascii wide
        $ext_02 = "ibnejdfjmmkpcnlpebbklmncjfeihjhd" ascii wide
        $ext_03 = "bfnaehdcgnoomnnidllghallandnmoof" ascii wide
        $ext_04 = "fhbohimaelbaakpkebpathgajjbcmofl" ascii wide
        $ext_05 = "hnfanknocfeofbddgcijnmhnfnkdnaad" ascii wide
        $ext_06 = "egjidmclbinglepboaecceandknbjckg" ascii wide
        $ext_07 = "bhghoamapcdpbophofhkbkmlpcadhbhi" ascii wide
        $ext_08 = "afbcbocneecolmionhpallocbocaminb" ascii wide
        $ext_09 = "idmeofnhbifmcononbaomihofohaccda" ascii wide
        $ext_10 = "cjelfplplebdgjenmdfichscannbache" ascii wide
        $ext_11 = "fhmfendgdocihloabdccaombepgfbcal" ascii wide
        $ext_12 = "odbfpeeihjdgnoengdiphbpbbeffmcia" ascii wide
        $ext_13 = "fnjhmkhhmkbjkkabndcnnoggdgannmej" ascii wide
        $ext_14 = "bfepbphgjaonmghgogofiphidgkbaand" ascii wide
        $ext_15 = "hdokiejkncaaaofgplenfjnmhnckcaah" ascii wide

        $target_file_01 = "Login Data" wide
        $target_file_02 = "Web Data" wide
        $target_file_03 = "Cookies" wide
        $target_file_04 = "Local State" wide
        $target_file_05 = "key4.db" wide
        $target_file_06 = "logins.json" wide

    condition:
        uint16(0) == 0x5A4D
        and pe.is_pe
        and filesize < 8MB
        and
        (
            (all of ($c2_boundary_*) and any of ($target_file_*))
            or
            ($ua_exact_01 and 2 of ($target_file_*))
            or
            (3 of ($c2_param_*) and 2 of ($log_fmt_*))
            or
            (2 of ($c2_param_*) and 4 of ($ext_*))
            or
            (3 of ($target_file_*) and 2 of ($log_fmt_*))
        )
}
