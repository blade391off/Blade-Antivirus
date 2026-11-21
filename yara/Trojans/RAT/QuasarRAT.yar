import "pe"

rule Detect_QuasarRAT
{
    meta:
        author = "blade391off"
        description = "Detect QuasarRAT"
        version = "1.0"
        threat_family = "Malware.DotNet.QuasarRAT"
        malware_type = "Remote Access Trojan"
        confidence = "High"

    strings:
        $pdb_1 = "\\Quasar\\Client\\" ascii
        $pdb_2 = "Quasar.Client" ascii

        $class_1 = "Quasar.Client.Config" ascii
        $class_2 = "Quasar.Client.Commands" ascii
        $class_3 = "Quasar.Client.Helper" ascii
        $class_4 = "Quasar.Client.Networking" ascii

        $msg_1 = "Disconnecting..." wide
        $msg_2 = "Handshake failed" wide

        $salt_1 = "QuasarClient" wide
        $salt_2 = "QuasarServer" wide

    condition:
        uint16(0) == 0x5A4D
        and filesize > 15KB
        and filesize < 3MB
        and (
            pe.imports("mscoree.dll", "_CorExeMain")
            or pe.imports("mscoree.dll", "_CorDllMain")
        )
        and (
            1 of ($pdb_*)
            or 2 of ($class_*)
            or (
                all of ($msg_*)
                and 1 of ($salt_*)
            )
        )
}
