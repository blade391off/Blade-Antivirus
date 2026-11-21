import "pe"
import "hash"

rule Target_Family_NavalnyPass_2000
{
    meta:
        author = "blade391off"
        description = "Detect Navalny ahahahah"
        date = "2026-08-18"
        version = "3.1"
        confidence = "high"
        detection_type = "hash_and_static"
        reference = "ANY.RUN behavioral report"

    strings:
        $name_1 = "navalny pass - 2000.exe" ascii wide nocase
        $name_2 = "winlocker.exe" ascii wide nocase

        $dll_1 = "php_squall.dll" ascii wide nocase
        $dll_2 = "php5ts.dll" ascii wide nocase

        $path_1 = "\\\\Temp\\\\ext\\\\php\\\\" ascii wide nocase

        $zone_1 = "Internet Settings\\ZoneMap" ascii wide nocase
        $zone_2 = "ProxyBypass" ascii wide nocase
        $zone_3 = "IntranetName" ascii wide nocase
        $zone_4 = "UNCAsIntranet" ascii wide nocase
        $zone_5 = "AutoDetect" ascii wide nocase

        $api_1 = "RegSetValueExA" ascii
        $api_2 = "RegSetValueExW" ascii
        $api_3 = "CreateProcessA" ascii
        $api_4 = "CreateProcessW" ascii

    condition:
        uint16(0) == 0x5A4D
        and filesize <= 20MB
        and pe.is_pe
        and
        (
            (
                hash.md5(0, filesize) == "86a1cbee2b7dc5d64051c83c82c8d02b"
                or hash.sha256(0, filesize) == "d3f47cd85c525a0c3ed855949bf27023c27b24c51d388166d72d4fa8cae4c2f5"
                or hash.md5(0, filesize) == "cf6c595d3e5e9667667af096762fd9c4"
                or hash.sha256(0, filesize) == "593e60cc30ae0789448547195af77f550387f6648d45847ea244dd0dd7abf03d"
                or hash.md5(0, filesize) == "02ee6a3424782531461fb2f10713d3c1"
                or hash.sha256(0, filesize) == "ead58c483cb20bcd57464F8A4929079539D634F469B213054BF737D227C026DC"
                or hash.md5(0, filesize) == "6ff84bc8812b8c079fa6de68cf36ab59"
                or hash.sha256(0, filesize) == "7587e29919a56b6f94675e49208e1ae908bcab09363734d846502c3b4ad54326"
                or hash.md5(0, filesize) == "58b58875a50a0d8b5e7be7d6ac685164"
                or hash.sha256(0, filesize) == "2a0aa0763fdef9c38c5dd4d50703f0c7e27f4903c139804ec75e55f8388139ae"
                or hash.md5(0, filesize) == "c9aff68f6673fae7580527e8c76805b6"
                or hash.sha256(0, filesize) == "9b2c8b8c4cec301c4303F58CA4E8B261D516F10FEB24573B092DFCCC263BAEA4"
                or hash.md5(0, filesize) == "9f93492e155d1bf27b8077e991e6a5a0"
                or hash.sha256(0, filesize) == "43eef3b68ebaab3efbe15eb3046281e380aa78003a0eda8757a9e44f6a59ec7f"
                or hash.md5(0, filesize) == "566ed4f62fdc96f175afedd811fa0370"
                or hash.sha256(0, filesize) == "e17cd94c08fc0e001a49f43a0801cea4625fb9aee211b6dfebebec446c21f460"
            )
            or
            (
                pe.machine == 332
                and
                (
                    (
                        $name_2
                        and 2 of ($dll_*)
                        and $path_1
                        and ($api_3 or $api_4)
                    )
                    or
                    (
                        $zone_1
                        and 3 of ($zone_2, $zone_3, $zone_4, $zone_5)
                        and ($api_1 or $api_2)
                    )
                    or
                    (
                        $name_1
                        and $name_2
                        and 1 of ($dll_*)
                    )
                )
            )
        )
}
