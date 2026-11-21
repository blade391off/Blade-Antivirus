rule Mamba_2FA_High_Confidence
{
    meta:
        description = "High-confidence detection of Mamba 2FA phishing-kit artifacts"
        author = "blade391off"
        reference = "https://any.run"
        target = "Mamba 2FA"
        confidence = "high"

    strings:
        $socket_io = "socket.io" ascii nocase
        $socket_connect = "io.connect" ascii
        $socket_emit = "socket.emit" ascii
        $socket_on = "socket.on" ascii

        $fp_ua = "navigator.userAgent" ascii
        $fp_lang = "navigator.language" ascii
        $fp_platform = "navigator.platform" ascii
        $fp_screen = "screen.width" ascii
        $fp_timezone = "getTimezoneOffset" ascii

        $ms_login = "://microsoftonline.com" ascii nocase
        $ms_loginfmt = "loginfmt" ascii nocase
        $ms_passwd = "passwd" ascii nocase

        $aitm_1 = "session" ascii nocase
        $aitm_2 = "token" ascii nocase
        $aitm_3 = "redirect_uri" ascii nocase
        $aitm_4 = "client_id" ascii nocase

        $url_mamba = /\/[mno]\/\?[A-Za-z0-9+\/]{30,}=*/ ascii

    condition:
        filesize < 3MB and
        (
            (
                2 of ($socket_*) and
                3 of ($fp_*) and
                all of ($ms_*)
            )
            or
            (
                1 of ($socket_*) and
                3 of ($fp_*) and
                all of ($ms_*) and
                2 of ($aitm_*)
            )
            or
            (
                $url_mamba and
                1 of ($socket_*) and
                2 of ($fp_*) and
                $ms_login
            )
        )
}


rule Mamba_2FA_Generic
{
    meta:
        description = "Generic Mamba 2FA phishing-kit detection with conservative correlation"
        author = "blade391off"
        reference = "https://any.run"
        target = "Mamba 2FA"
        confidence = "medium"

    strings:
        $s1 = "socket.io" ascii nocase
        $s2 = "io.connect" ascii
        $s3 = "socket.emit" ascii
        $s4 = "socket.on" ascii
        $s5 = "WebSocket" ascii

        $f1 = "navigator.userAgent" ascii
        $f2 = "navigator.language" ascii
        $f4 = "navigator.platform" ascii
        $f7 = "screen.width" ascii
        $f9 = "getTimezoneOffset" ascii

        $loginfmt = "loginfmt" ascii nocase
        $passwd = "passwd" ascii nocase

        $ms1 = "://microsoftonline.com" ascii nocase
        $ms2 = "oauth2" ascii nocase
        $ms4 = "redirect_uri" ascii nocase

        $net1 = "fetch(" ascii
        $net2 = "XMLHttpRequest" ascii

    condition:
        filesize < 3MB and
        (
            (
                2 of ($s*) and
                3 of ($f*) and
                $loginfmt and
                $passwd
            )
            or
            (
                1 of ($s*) and
                3 of ($f*) and
                $loginfmt and
                $passwd and
                2 of ($ms*)
            )
            or
            (
                1 of ($s*) and
                3 of ($f*) and
                all of ($ms*) and
                1 of ($net*)
            )
        )
}


rule Mamba_2FA_URL_Artifact
{
    meta:
        description = "Conservative Mamba 2FA URL artifact detection"
        author = "blade391off"
        reference = "https://any.run"
        target = "Mamba 2FA"
        confidence = "high"

    strings:
        $mamba_url_strict = /\/[mno]\/\?[A-Za-z0-9+\/]{35,}=*/ ascii

        $socket = "socket.io" ascii nocase
        $emit = "socket.emit" ascii
        $websocket = "WebSocket" ascii

        $fp1 = "navigator.userAgent" ascii
        $fp2 = "navigator.language" ascii
        $fp3 = "navigator.platform" ascii

        $ms = "://microsoftonline.com" ascii nocase

    condition:
        filesize < 1MB and
        $mamba_url_strict and
        (
            (
                1 of ($socket, $emit, $websocket) and
                2 of ($fp*) and
                $ms
            )
            or
            (
                1 of ($socket, $emit) and
                all of ($fp*)
            )
        )
}


rule Mamba_2FA_Microsoft_AiTM
{
    meta:
        description = "Detects correlated Microsoft credential and AiTM indicators associated with Mamba 2FA"
        author = "blade391off"
        reference = "https://any.run"
        target = "Mamba 2FA"
        confidence = "high"

    strings:
        $login = "loginfmt" ascii nocase
        $password = "passwd" ascii nocase

        $microsoft_login = "://microsoftonline.com" ascii nocase

        $oauth = "oauth2" ascii nocase
        $authorize = "authorize" ascii nocase
        $redirect = "redirect_uri" ascii nocase
        $client = "client_id" ascii nocase

        $socket_io = "socket.io" ascii nocase
        $socket_emit = "socket.emit(" ascii

    condition:
        filesize < 3MB and
        $login and
        $password and
        $microsoft_login and
        3 of ($oauth, $authorize, $redirect, $client) and
        1 of ($socket_io, $socket_emit)
}


rule Mamba_2FA
{
    meta:
        description = "Mamba 2FA phishing-kit detection collection"
        author = "blade391off"
        reference = "https://any.run"
        target = "Mamba 2FA"

    condition:
        Mamba_2FA_High_Confidence or
        Mamba_2FA_Generic or
        Mamba_2FA_URL_Artifact or
        Mamba_2FA_Microsoft_AiTM
}
