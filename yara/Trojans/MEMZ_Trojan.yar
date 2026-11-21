rule MEMZ_Trojan {
    meta:
        author = "blade391off"
        description = "Detects the MEMZ Trojan payload and its specific destruct indicators"
        date = "2026-08-08"
        version = "1.0"
        severity = "Critical"

    strings:
        $msg_0 = "YOUR COMPUTER HAS BEEN FUCKED BY THE MEMZ TROJAN" ascii wide
        $msg_1 = "What you are about to see is the MEMZ Trojan" ascii wide
        $msg_2 = "Enjoy the final moments of your stable OS" ascii wide
        $msg_3 = "STILL USING THIS COMPUTER?" ascii wide

        $search_0 = "how+to+remove+a+virus" ascii wide
        $search_1 = "mario+paint+music" ascii wide
        $search_2 = "how+to+get+money" ascii wide
        $search_3 = "google.co.ck" ascii wide

        $cmd_mbr = "\\\\.\\PhysicalDrive0" ascii wide

    condition:
        uint16(0) == 0x5A4D and filesize < 500KB and (
            2 of ($msg_*) or
            (1 of ($msg_*) and 2 of ($search_*)) or
            ($cmd_mbr and 1 of ($msg_*))
        )
}
