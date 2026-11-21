import "pe"

rule RedLine_Triage {
    meta:
        rule_id = "REDLINE-0001"
        version = "1.0"
        confidence = "Medium"
        reference = "Internal Research"
        tlp = "WHITE"
        description = "Fast triage rule for RedLine Stealer payloads forcing mandatory WCF network layer validation"
        author = "blade391off"
        date = "2026-08-03"
        severity = "High"
        malware_family = "RedLine"

    strings:
        $wcf_01 = "IRemoteEndpoint" ascii wide
        $wcf_02 = "IterateArgs" ascii wide
        $wcf_03 = "CommandLineUpdate" ascii wide
        
        $sys_01 = "scannedUser" ascii wide
        $sys_02 = "hardwares" ascii wide
        
        $cfg_01 = "GeckoRepository" ascii wide
        $cfg_02 = "AllWallets" ascii wide

    condition:
        pe.is_pe and 
        filesize < 2000000 and 
        (
            (2 of ($wcf_*) and 1 of ($sys_*)) or 
            (2 of ($wcf_*) and 1 of ($cfg_*)) or
            (1 of ($wcf_*) and 1 of ($sys_*) and 1 of ($cfg_*))
        )
}
