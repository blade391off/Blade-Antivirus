import "pe"

rule PathWiper
{       
          meta:
          author = "blade391off"
          description = "This rule detected the PathWiper malware in good confidence"
          license = "MIT"
          repo = "Ukrainian Yara Rules"
          threat_actor = "APT44"

strings:
     $hex_1 = { c7 45 e0 eb cc b1 58 66 89 75 e4 e8 ?? ?? ?? ?? 8b 8d 52 eb ff ff 33 c8 66 89 4d e6 b9 8f bc 00 00 }
     $hex_2 = { c6 45 fc 00 85 c0 0f 85 9a 00 00 00 8b 45 f0 83 c0 18 89 45 f0 3b 45 ec }
     $hex_3 = { 50 8d 45 e0 89 75 ec 50 c7 45 f0 37 34 ba f3 c7 45 f4 1d ec cd a2 } 

     $drop_1 = "sha256sum.exe"

condition:
      pe.is_pe and
      2 of ($hex_*) and
      all of ($drop*)
}
      

     
