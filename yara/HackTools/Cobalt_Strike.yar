rule Detect_Cobalt_Strike {
    meta:
        author = "blade391off"
        description = "Detect Cobalt Strike"
        version = "1.0"
    strings:
        $op_reflective_loader_x86 = { 55 89 e5 53 56 57 8c c8 83 ec ?? e8 00 00 00 00 5b 81 eb ?? ?? ?? ?? 8b 83 ?? ?? ?? ?? 89 45 ?? 8d 83 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 89 45 }
        $op_reflective_loader_x64 = { 48 89 5c 24 08 48 89 74 24 10 48 89 7c 24 18 41 56 48 83 ec 20 4c 8b f1 e8 00 00 00 00 59 49 81 e9 ?? ?? ?? ?? 41 8b 86 ?? ?? ?? ?? 48 8d 0d }
        $op_beacon_decode_config = { 8a 04 0e 30 04 0a 42 3b 55 ?? 7c f2 }
        $op_stealth_thread_x64 = { 4c 8b d1 4c 8b d9 4d 85 d2 74 ?? 41 83 3a 00 74 ?? 4d 8b 02 4d 85 c0 74 ?? 41 ff d0 }
        $op_pipe_v4_obfuscated = { c6 44 24 ?? 5c c6 44 24 ?? 5c c6 44 24 ?? 2e c6 44 24 ?? 5c c6 44 24 ?? 70 c6 44 24 ?? 69 c6 44 24 ?? 70 c6 44 24 ?? 65 }
        $cs_named_pipe_pattern = { 5c 00 5c 00 2e 00 5c 00 70 00 69 00 70 00 65 00 5c 00 [2-30] 5f 00 }
        $c2_config_block_x86 = { c7 45 ?? 01 00 00 00 c7 45 ?? 02 00 00 00 66 c7 45 ?? ?? ?? }
        $c2_config_block_x64 = { 41 c7 00 01 00 00 00 41 c7 40 ?? 02 00 00 00 45 66 c7 40 }
        $internal_status_msg_01 = { 46 61 69 6c 65 64 20 74 6f 20 63 72 65 61 74 65 20 73 65 72 76 69 63 65 }
        $internal_status_msg_02 = { 25 73 20 61 73 20 25 73 5c 5c 25 73 }
        $internal_status_msg_03 = { 23 25 64 20 4a 75 73 74 20 69 6e 20 74 69 6d 65 20 43 4c 52 }
        $internal_status_msg_04 = { 43 6f 75 6c 64 20 6e 6f 74 20 6f 70 65 6e 65 64 20 70 72 6f 63 65 73 73 }
        $internal_status_msg_05 = { 5c 5c 25 73 5c 5c 70 69 70 65 5c 5c 25 73 }
    condition:
        uint16(0) == 0x5a4d and
        (
            (1 of ($op_reflective_loader*) and 1 of ($c2_config*)) or
            ($op_beacon_decode_config and 2 of ($internal_status_msg*)) or
            ($op_stealth_thread_x64 and $cs_named_pipe_pattern) or
            ($op_pipe_v4_obfuscated and 1 of ($internal_status_msg*)) or
            (3 of ($internal_status_msg*))
        )
}
