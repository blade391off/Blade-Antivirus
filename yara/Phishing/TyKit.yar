rule TyKit
{
    meta:
        description = "Detects TyKit phishing-kit artifacts targeting Microsoft 365"
        author = "blade391off"
        reference = "https://any.run/malware-trends/tykit/"
        target = "TyKit"
        type = "phishingkit"
        confidence = "high"

    strings:
        $svg = "<svg" ascii nocase
        $script = "<script" ascii nocase

        $api_validate = "/api/validate" ascii nocase
        $api_login = "/api/login" ascii nocase
        $xphp = "/x.php" ascii nocase

        $query_s = /\/\?s=[A-Za-z0-9+\/]{20,}=*/ ascii

        $ms_login = "login.microsoftonline.com" ascii nocase
        $loginfmt = "loginfmt" ascii nocase
        $passwd = "passwd" ascii nocase

        $eval = "eval(" ascii
        $xor = "charCodeAt(" ascii
        $fromchar = "String.fromCharCode" ascii
        $atob = "atob(" ascii

        $redirect1 = "location.href" ascii nocase
        $redirect2 = "location.replace" ascii nocase
        $redirect3 = "location.assign" ascii nocase
        $redirect4 = "window.location" ascii nocase

        $fingerprint1 = "navigator.userAgent" ascii
        $fingerprint2 = "navigator.language" ascii
        $fingerprint3 = "navigator.platform" ascii
        $fingerprint4 = "screen.width" ascii
        $fingerprint5 = "screen.height" ascii

    condition:
        filesize < 5MB and
        (
            (
                $svg and
                $script and
                2 of ($api_*) and
                1 of ($xphp, $query_s) and
                2 of ($eval, $xor, $fromchar, $atob)
            )
            or
            (
                2 of ($api_*) and
                $xphp and
                $ms_login and
                all of ($loginfmt, $passwd)
            )
            or
            (
                $query_s and
                2 of ($api_*) and
                2 of ($redirect*) and
                3 of ($fingerprint*)
            )
            or
            (
                $svg and
                $script and
                $xphp and
                all of ($loginfmt, $passwd) and
                2 of ($eval, $xor, $fromchar)
            )
        )
}
