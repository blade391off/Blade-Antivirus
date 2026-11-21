import "pe"

rule Osiris
{
    meta: 
       author = "blade391off"
       description = "This rule detected Osiris"
       repo = "Ukrainian Yara Rules"
       yara_version = "4.5.0"
       threat_actor = "maybe Inc.Ransomware"

strings:
        $domains_1 = "ausare.net" ascii wide nocase
        $domains_2 = "wesir.net" ascii wide nocase 

        $dropped_1 = "33.exe" ascii wide nocase
        $dropped_2 = "Kaz.exe" ascii wide nocase
        $dropped_3 = "Payload.exe" ascii wide nocase
        $dropped_4 = "Osiris-MESSAGE.txt" ascii wide nocase

condition:
       pe.is_pe and // update 16.10.2026 remove 15 mb check
       1 of ($domains_*) and 
       2 of ($dropped_*)
}
