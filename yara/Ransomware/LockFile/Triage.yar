import "pe"

rule LockFile_Triage
{
          meta: 
            author = "blade391off"
            description = "Detect Lock file"
            threat_actor = "idk"

strings:

$text_1 = "LOCKFILE" ascii wide nocase
$text_2 = "ALL YOUR IMPORTANT FILES ARE ENCRYPTED!" ascii wide nocase
$text_3 = "Any attempts to restore your files with the thrid-party software will be fatal for your files!" ascii wide nocase
$text_4 = "There is only one way to get your files back:" ascii wide nocase

condition: 

pe.is_pe and
(2 of ($text_*))
}



         


