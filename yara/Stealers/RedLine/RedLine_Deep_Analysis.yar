import "pe"

rule RedLine_Deep_Analysis {
    meta:
        rule_id = "REDLINE-0002"
        version = "1.0"
        confidence = "High"
        reference = "Internal Research"
        tlp = "WHITE"
        description = "Deep analysis rule for RedLine Stealer focusing on resilient cross-group intersections"
        author = "blade391off"
        date = "2026-08-03"
        severity = "Critical"
        malware_family = "RedLine"

    strings:
        $core_01 = "scannedUser" ascii wide
        $core_02 = "scannedFiles" ascii wide
        $core_03 = "ObjectLog" ascii wide

        $cfg_01 = "AllWallets" ascii wide
        $cfg_02 = "UserPorts" ascii wide
        $cfg_03 = "StringDecrypt" ascii wide

        $browser_01 = "BrowserProfile" ascii wide
        $browser_02 = "GeckoRepository" ascii wide
        $browser_03 = "DisplayHelper" ascii wide

        $crypto_01 = "HolderName" ascii wide
        $crypto_02 = "encrypted_key" ascii wide

        $net_01 = "IRemoteEndpoint" ascii wide
        $net_02 = "IterateArgs" ascii wide
        $net_03 = "CommandLineUpdate" ascii wide

    condition:
        pe.is_pe and 
        pe.imports("mscoree.dll", "_CorExeMain") and 
        filesize < 1200000 and 
        (
            (2 of ($core_*) and 2 of ($cfg_*)) or
            (2 of ($core_*) and 2 of ($browser_*)) or
            (2 of ($core_*) and 2 of ($net_*)) or
            (2 of ($cfg_*) and 2 of ($net_*)) or
            (1 of ($crypto_*) and 2 of ($core_*))
        )
}
