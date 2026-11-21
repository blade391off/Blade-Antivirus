import "pe"
import "hash"

rule APT29_MiniDuke_Hash
{
    meta:
        description = "Detect MiniDuke"
        author = "blade391off"
        date = "2026-08-31"
        category = "apt"
        threat_actor = "APT29"
        malware_family = "MiniDuke"

    condition:
        hash.md5(0, filesize) == "d169e6bda4800f1c34a3458316223b5d" or
        hash.sha256(0, filesize) == "f5062c069eb85b140af60b64d1f27464e83c3e76a6cfd7be51543ed2d5f27663"
}

rule APT29_MiniDuke_Static
{
    meta:
        description = "Detect MiniDuke"
        author = "blade391off"
        date = "2026-08-31"
        category = "apt"
        threat_actor = "APT29"
        malware_family = "MiniDuke"

    strings:
        $dll = "UserCache.dll" ascii wide
        $feed = "/news/feed.php" ascii
        $forum = "/forum/viewtopic.php" ascii
        $search = "/search/search.php" ascii
        $shared = "/shared/data.php" ascii

    condition:
        uint16(0) == 0x5A4D and
        pe.number_of_sections >= 2 and
        pe.number_of_sections <= 12 and
        filesize < 10MB and
        (
            2 of ($feed, $forum, $search, $shared) or
            ($dll and 1 of ($feed, $forum, $search, $shared))
        )
}
