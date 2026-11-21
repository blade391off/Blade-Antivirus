import "pe"

rule LockFile_Deep
{
    meta:
        author = "blade391off"
        description = "Detect LockFile"
        threat_actor = "idk"

    strings:
        $header_1 = "LOCKFILE" ascii wide nocase
        $header_2 = "LOCK FILE" ascii wide nocase
        
        $txt_1 = "ALL YOUR IMPORTANT FILES ARE ENCRYPTED!" ascii wide nocase
        $txt_2 = "Any attempts to restore your files with the thrid-party software will be fatal for your files!" ascii wide nocase
        $txt_3 = "Restore you data posible only buying private key from us." ascii wide nocase
        $txt_4 = "There is only one way to get your files back:" ascii wide nocase

        $contact_1 = "qTox ID: B2F873769EB6B508EBC2103DDEB7366CEFB7B09AB8314DAD0C4346169072" ascii wide nocase
        $contact_2 = "Email: contact@contipauper.com" ascii wide nocase

condition:

pe.is_pe and 
2 of ($header_*) and 
4 of ($txt_*) and 
1 of ($contact_*) 
}
