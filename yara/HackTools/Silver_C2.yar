rule Detect_Sliver_C2 {
    meta:
        author = "blade391off"
        description = "Detect Sliver C2"
        malware_family = "Sliver_C2"
        severity = "Critical"
        reference = "Internal Threat Intelligence / BishopFox Sliver Research"
        version = "1.0"
        detection_type = "Both"
    strings:
        $go_pclntab_120 = { fb ff ff ff 00 00 01 14 }
        $go_pclntab_121 = { fb ff ff ff 00 00 01 15 }
        $go_pclntab_122 = { fb ff ff ff 00 00 01 16 }
        $go_uuid_x64 = { 48 8d [1-7] e8 [4] 48 8b [1-5] 48 8d [1-7] e8 [4] 48 83 c4 } private
        $op_curve25519 = { 48 8b [2-5] 48 8b [2-5] 48 89 [2-5] e8 [4] 48 8d [2-5] 48 89 [2-5] e8 [4] 48 8b } private
        $op_base58 = { 81 [1-6] 7c [1-3] 48 8b [1-5] 48 8b [1-5] 48 01 [1-3] 48 8b [1-5] 48 89 [1-5] e8 } private
        $pb_const = "sliverpb.Constant" ascii private
        $pb_env = "sliverpb.Envelope" ascii private
        $pb_reg = "sliverpb.RegisterInfo" ascii private
        $pb_piv = "sliverpb.Pivot" ascii private
        $pb_spw = "sliverpb.Spawn" ascii private
        $dns_canary = "canary.sliver.sh" ascii nocase private
    condition:
        (uint16(0) == 0x5a4d or uint32(0) == 0x464c457f or uint32(0) == 0xbebafeca or not uint16(0)) and
        filesize < 30MB and
        (
            (1 of ($go_pclntab*) or not uint16(0)) and
            (
                3 of ($pb_*) or
                ($op_curve25519 and $op_base58) or
                ($dns_canary and $go_uuid_x64) or
                (1 of ($pb_*) and $op_base58 and $op_curve25519)
            )
        )
}
