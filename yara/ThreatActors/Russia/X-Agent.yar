import "pe"
import "hash"

rule APT28_XAgent_CHOPSTICK
{
    meta:
        description = "Detect X-Agent"
        author = "blade391off"
        date = "2026-08-31"
        category = "apt"
        threat_actor = "APT28"
        malware_family = "CHOPSTICK"

    strings:
        $xagent = "X-Agent" ascii nocase
        $xagent2 = "Xagent" ascii nocase
        $splm = "SPLM" ascii nocase
        $chopstick = "CHOPSTICK" ascii nocase
        $sofacy = "Backdoor.SofacyX" ascii nocase
        $unique_tmp = "jhuhugit.tmp" ascii
        $twain = "twain_64.dll" ascii nocase
        $rundll32 = "rundll32.exe" ascii nocase
        $registry = "CurrentVersion\\Run" ascii nocase
        $userinit = "UserInitMprLogonScript" ascii nocase
        $keylog = "keylog" ascii nocase
        $screenshot = "screenshot" ascii nocase
        $command = "command" ascii nocase

    condition:
        uint16(0) == 0x5A4D and
        pe.number_of_sections >= 2 and
        pe.number_of_sections <= 12 and
        filesize < 10MB and
        (
            hash.sha256(0, filesize) == "255d64ff18a16db8a2cf3df09e1e2d4d81237ebdc138676b701c34d0b11df052" or
            hash.sha256(0, filesize) == "90ac7bf6e0b76245296e194bc1bd8a6388d013b7e11be906ae0352ff22c3f472" or
            hash.sha256(0, filesize) == "c6e8e8b0b56b3e8e19db9a35e80d463b2f9241b3156fa301d0bc881ba08d4b31" or
            hash.sha256(0, filesize) == "3a6b8e217d890bfaee013d567c9cde2f871340b1ee06efda156a29774debcde1" or
            hash.sha256(0, filesize) == "f8352b217e056ba83cd3dffc71a3962b405e3ecbc3970b8a1c97a5f6e80b2a3a" or
            hash.md5(0, filesize) == "13d31eb49989f6da409403d6d0ffbe0c" or
            hash.md5(0, filesize) == "61159cc4cd1827b508f7db08e16279f0" or
            $unique_tmp or
            (
                2 of ($xagent, $xagent2, $splm, $chopstick, $sofacy) and
                1 of ($keylog, $screenshot, $command)
            ) or
            (
                $rundll32 and
                $twain
            ) or
            (
                2 of ($registry, $userinit) and
                1 of ($xagent, $xagent2, $splm, $chopstick, $sofacy)
            )
        )
}
