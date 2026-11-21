rule Triage_Petya_Family_Blade391off {
    meta:
        author = "blade391off"
        description = "Triage rule for Petya, Mischa, NotPetya, ExPetr, and GoldenEye ransomware variants"
        threat_level = "Critical"
        date = "2026-08-11"

    strings:
        $petya_1 = "Your computer's hard drive has been encrypted" ascii
        $petya_2 = "http://petya" ascii fullword
        
        $mischa_1 = "YOUR FILES ARE ENCRYPTED" ascii
        $mischa_2 = "YOUR PERSONAL IDENTIFICATION CODE" ascii
        $mischa_3 = "mischapasi" ascii fullword

        $notpetya_1 = "wowsmith123456" ascii fullword
        $notpetya_2 = "Send $300 worth of Bitcoin to following address" ascii
        $notpetya_3 = "wowsmith123456@posteo.net" ascii

        $goldeneye_1 = "YOUR_FILES_ARE_ENCRYPTED.TXT" ascii wide
        $goldeneye_2 = "GoldenEye" ascii fullword

    condition:
        uint16(0) == 0x5A4D and filesize < 15MB and (
            2 of ($petya_*) or 
            2 of ($mischa_*) or 
            2 of ($goldeneye_*) or 
            any of ($notpetya_*)
        )
}
