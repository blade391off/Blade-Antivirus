import "pe"
import "math"

rule Zeus_Trojan_10_Layers {
    meta:
        author = "blade391off"
        description = "Production-grade detection rule for Zeus banking trojan core payloads"
        date = "2026-08-08"
        version = "1.1"
        severity = "Critical"
        sharing = "TLP:CLEAR"

    strings:
        $cfg_0 = "coreinfo" ascii fullword
        $cfg_1 = "userinfo" ascii fullword
        $cfg_2 = "localinfo" ascii fullword

        $api_hook_0 = "HttpSendRequestA" ascii fullword
        $api_hook_1 = "HttpSendRequestW" ascii fullword
        $api_hook_2 = "HttpQueryInfoA" ascii fullword
        $api_hook_3 = "InternetReadFile" ascii fullword

        $api_inj_0 = "NtCreateThreadEx" ascii fullword
        $api_inj_1 = "ZwMapViewOfSection" ascii fullword
        $api_inj_2 = "UnmapViewOfSection" ascii fullword

        $api_crypto_0 = "CryptAcquireContextA" ascii fullword
        $api_crypto_1 = "CryptGenRandom" ascii fullword
        $api_crypto_2 = "CryptDecrypt" ascii fullword

        $uac_0 = "requireAdministrator" ascii wide nocase
        $uac_1 = "asInvoker" ascii wide nocase

        $hex_rc4_zeus = {
            8A [0-4] 02 [0-4] 8A [0-4] 88
            [0-4] 88 [0-4] 03 [0-4] 81 [0-4] FF
            00 00 00
        }

    condition:
        uint16(0) == 0x5A4D
        and filesize > 20KB
        and filesize < 5MB
        and not pe.is_dll()
        and pe.number_of_sections >= 3
        and pe.number_of_sections <= 7
        and pe.number_of_signatures == 0

        and (
            for any i in (0..pe.number_of_sections - 1) : (
                (
                    pe.sections[i].name matches /^\.?[Tt][Ee][Xx][Tt]$/
                    or
                    pe.sections[i].name matches /^[Cc][Oo][Dd][Ee]$/
                )
                and pe.sections[i].raw_data_size > 0
                and pe.sections[i].raw_data_size < 2MB
                and math.entropy(
                    pe.sections[i].raw_data_offset,
                    pe.sections[i].raw_data_size
                ) > 7.2
            )
        )

        and (
            pe.imports("kernel32.dll", "VirtualAlloc")
            or
            pe.imports("kernel32.dll", "CreateProcessA")
        )

        and (
            (all of ($cfg_*) and 2 of ($api_hook_*))
            or
            ($hex_rc4_zeus and 2 of ($api_inj_*) and 1 of ($api_crypto_*))
            or
            (2 of ($cfg_*) and 2 of ($api_crypto_*) and 1 of ($uac_*))
        )
}
