rule Detect_Impacket_Tools {
    meta:
        author = "blade391off"
        description = "Detect Impacket-Based Offensive Tools Architecture"
        malware_family = "Impacket_Tools"
        severity = "Critical"
        reference = "Internal Threat Intelligence / Core Impacket Network Architecture"
        version = "1.1"
        detection_type = "Both"
    strings:
        $py_pyc_magic_01 = { 6f 0d 0d 0a }
        $py_pyc_magic_02 = { a7 0d 0d 0a }
        $py_pyc_magic_03 = { a8 0d 0d 0a }
        $py_pyc_magic_04 = { c3 0d 0d 0a }
        $py_pyc_magic_05 = { 10 0d 0d 0a }
        $py_pyc_magic_06 = { c7 0d 0d 0a }
        $py_struct_b_ndr = { 42 00 00 00 [1-4] 01 00 00 00 [1-4] cc c1 2d 57 14 b2 2e 4c 8b d2 3b 1c 06 9c c3 a3 } private
        $imp_smb3_wire_anomaly = { fe 53 4d 42 [4-16] ff ff 00 00 [1-4] 00 40 00 00 [1-8] 00 00 10 00 } private
        $imp_dcerpc_uuid_anomaly = { 05 00 0b [1-3] 10 00 00 00 [1-4] b8 10 00 00 00 00 00 00 [1-4] 04 5d 8a 8a 1f 1c 1b 17 } private
        $imp_ntlm_opaque_anomaly = { 4e 54 4c 4d 53 53 50 00 01 00 00 00 [1-4] 05 02 08 a2 [1-8] 00 00 00 00 00 00 00 00 } private
        $core_string_01 = "impacket.dcerpc.v5" ascii private
        $core_string_02 = "impacket.smbconnection" ascii private
        $core_string_03 = "impacket.examples.ntlmrelayx" ascii private
        $core_string_04 = "impacket.examples.psexec" ascii private
        $core_string_05 = "impacket.examples.secretsdump" ascii private
    condition:
        (uint16(0) == 0x5a4d or uint32(0) == 0x464c457f or not uint16(0)) and
        filesize < 35MB and
        (
            (1 of ($py_pyc_magic*) and (all of ($core_string_*) or 3 of ($core_string_*))) or
            (not uint16(0) and 3 of ($core_string_*)) or
            ($py_struct_b_ndr and $imp_dcerpc_uuid_anomaly and $imp_smb3_wire_anomaly) or
            ($imp_smb3_wire_anomaly and $imp_ntlm_opaque_anomaly) or
            ($py_struct_b_ndr and $imp_ntlm_opaque_anomaly and 1 of ($core_string_*))
        )
}
