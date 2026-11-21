rule Detect_Carberp {
    meta:
        author = "blade391off"
        description = "Detect Carberp"
        version = "1.1"
        threat_family = "Malware.Win32.Carberp"
        malware_type = "Banking Trojan"
        confidence = "High"

    strings:
        $src_bot_1 = "== START BOT ==" ascii
        $src_bot_2 = "Instance hash: %08X%08X" ascii
        $src_bot_3 = "GetCommand error, status: %d" ascii
        $src_bot_4 = "plgdef.dat" ascii wide
        $src_bot_5 = "cfg.dat" ascii wide

        $pipe_1 = "\\\\.\\pipe\\sh_hostpipe" ascii wide
        $pipe_2 = "\\\\.\\pipe\\carberp_pipe" ascii wide

        $mutex_1 = "Global\\sh_host_mutex" ascii wide
        $mutex_2 = "Global\\carberp_mutex" ascii wide

        $hook_1 = "NtWriteVirtualMemory" ascii
        $hook_2 = "NtResumeThread" ascii
        $hook_3 = "InternetReadFile" ascii
        $hook_4 = "HttpSendRequest" ascii

    condition:
        uint16(0) == 0x5A4D and 
        uint16(uint32(0x3C)) == 0x4550 and 
        filesize > 20KB and filesize < 5MB and 
        (
            (2 of ($src_bot_*)) or 
            (1 of ($pipe_*) and 1 of ($mutex_*)) or 
            (all of ($hook_*) and 1 of ($src_bot_*))
        )
}
