import "pe"

rule Detect_AsyncRAT
{
    meta:
        author = "blade391off"
        description = "Detect AsyncRAT"
        version = "1.0"
        threat_family = "Malware.DotNet.AsyncRAT"
        malware_type = "Remote Access Trojan"
        confidence = "High"

    strings:
        $pdb_1 = "\\AsyncRAT\\" ascii
        $pdb_2 = "AsyncRAT.Properties" ascii

        $class_1 = "AsyncRAT.Connection" ascii
        $class_2 = "AsyncRAT.Settings" ascii
        $class_3 = "AsyncRAT.Messaging" ascii

        $salt_1 = "AsyncRAT" wide
        $salt_2 = "Packet" wide
        $salt_3 = "ClientInfo" wide

    condition:
        uint16(0) == 0x5A4D
        and filesize > 20KB
        and filesize < 4MB
        and (
            pe.imports("mscoree.dll", "_CorExeMain")
            or pe.imports("mscoree.dll", "_CorDllMain")
        )
        and (
            1 of ($pdb_*)
            or 2 of ($class_*)
            or all of ($salt_*)
        )
}
