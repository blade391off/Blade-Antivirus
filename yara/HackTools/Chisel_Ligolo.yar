rule Detect_Chisel_Ligolo {
    meta:
        author = "blade391off"
        description = "Detect Chisel and Ligolo-ng Tunneling Tools"
        malware_family = "Chisel_Ligolo"
        severity = "Critical"
        reference = "Internal Threat Intelligence / Go-Based Tunneling Frameworks"
        version = "1.2"
        detection_type = "Both"
    strings:
        $go_pclntab_120 = { fb ff ff ff 00 00 01 14 }
        $go_pclntab_121 = { fb ff ff ff 00 00 01 15 }
        $go_pclntab_122 = { fb ff ff ff 00 00 01 16 }
        $chisel_proto_01 = "chisel.Server" ascii private
        $chisel_proto_02 = "chisel.Client" ascii private
        $chisel_proto_03 = "chisel.Tunnel" ascii private
        $chisel_proto_04 = "chisel.Session" ascii private
        $ligolo_proto_01 = "ligolo.Agent" ascii private
        $ligolo_proto_02 = "ligolo.Proxy" ascii private
        $ligolo_proto_03 = "ligolo.Tunnel" ascii private
        $op_tun_alloc_x64 = { 48 8d [1-5] 48 8b [1-5] 4c 89 [1-5] e8 [1-4] 48 85 c0 74 [1-3] 48 8b [1-5] 48 8d [1-5] e8 } private
        $yamux_wire_magic = { c1 [1-4] 00 00 00 [1-3] 01 00 00 00 [1-2] 00 00 02 00 } private
        $smux_wire_magic = { 4d 55 [1-4] a1 00 [1-4] 01 00 00 00 [1-3] 02 00 00 00 } private
    condition:
        (uint16(0) == 0x5a4d or uint32(0) == 0x464c457f or uint32(0) == 0xbebafeca or not uint16(0)) and
        filesize < 25MB and
        (
            (1 of ($go_pclntab*) or not uint16(0)) and
            (
                (2 of ($chisel_proto*) and $smux_wire_magic) or
                (2 of ($ligolo_proto*) and $yamux_wire_magic) or
                ($smux_wire_magic and $op_tun_alloc_x64) or
                ($yamux_wire_magic and $op_tun_alloc_x64) or
                ($yamux_wire_magic and $smux_wire_magic)
            )
        )
}
