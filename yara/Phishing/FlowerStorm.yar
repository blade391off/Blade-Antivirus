rule FlowerStorm
{
    meta:
        description = "Detects FlowerStorm phishing-kit artifacts"
        author = "blade391off"
        reference = "https://any.run/malware-trends/flowerstorm/"
        target = "FlowerStorm"
        type = "phishingkit"
        confidence = "high"

    strings:
        $backend1 = "next.php" ascii nocase
        $backend2 = "/next.php" ascii nocase
        $backend3 = "next.php?" ascii nocase

        $ms_login = "login.microsoftonline.com" ascii nocase
        $loginfmt = "loginfmt" ascii nocase
        $passwd = "passwd" ascii nocase

        $jwt1 = "access_token" ascii nocase
        $jwt2 = "id_token" ascii nocase
        $jwt3 = "Bearer " ascii
        $jwt4 = "JWT" ascii

        $session1 = "sessionToken" ascii nocase
        $session2 = "sessionid" ascii nocase
        $session3 = "ESTSAUTH" ascii nocase
        $session4 = "ESTSAUTHPERSISTENT" ascii nocase

        $turnstile1 = "cf-turnstile" ascii nocase
        $turnstile2 = "turnstile.render" ascii nocase
        $turnstile3 = "challenges.cloudflare.com/turnstile" ascii nocase

        $title1 = "<title>Sprout" ascii nocase
        $title2 = "<title>Blossom" ascii nocase
        $title3 = "<title>Flower" ascii nocase
        $title4 = "<title>Leaf" ascii nocase

        $redirect1 = "location.href" ascii nocase
        $redirect2 = "location.replace" ascii nocase
        $redirect3 = "location.assign" ascii nocase

    condition:
        filesize < 5MB and
        (
            (
                1 of ($backend*) and
                $ms_login and
                $loginfmt and
                $passwd and
                2 of ($jwt*) and
                1 of ($session*)
            )
            or
            (
                1 of ($backend*) and
                $ms_login and
                $loginfmt and
                $passwd and
                1 of ($turnstile*) and
                1 of ($jwt*, $session*)
            )
            or
            (
                1 of ($backend*) and
                1 of ($title*) and
                $ms_login and
                $loginfmt and
                $passwd
            )
            or
            (
                1 of ($backend*) and
                1 of ($turnstile*) and
                all of ($ms_*, $loginfmt, $passwd) and
                2 of ($redirect*)
            )
        )
}
