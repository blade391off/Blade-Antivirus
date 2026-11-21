import "pe"

rule SalatStealer 
{

        meta:
           author = "blade391off"
           description = "Detect SalatStealer with deep analyze"
           category = "Stealer"
           threat_actor = "NyashTeam and Kapchenka"

strings:
        
        $u_1 = "/sa1at/" ascii wide nocase
        $u_2 = "/client/addclient" ascii wide nocase
        $u_3 = "/alive.php" ascii wide nocase

        
        $d_1 = "salat.cn" ascii wide
        $d_2 = "salator.es" ascii wide
        $d_3 = "salator.ru" ascii wide
        $d_4 = "websalat.top" ascii wide
        $d_5 = "wrat.in" ascii wide
        $d_6 = "sa1at.ru" ascii wide
        $d_7 = "webr.at" ascii wide
        $d_8 = "webrat.su" ascii wide
        $d_9 = "webrat.in" ascii wide
        $d_10 = "webrat.top" ascii wide
        $d_11 = "sa1atik.cn" ascii wide
        $d_12 = "wruser.org" ascii wide
        $d_13 = "posholnahuy.ru" ascii wide
        $d_14 = "pidorasina.ru" ascii wide
        $d_15 = "nyash.team" ascii wide

        
        $ip_1 = "150.241.64.21" ascii wide
        $ip_2 = "95.85.224.14" ascii wide
        $ip_3 = "95.85.231.199" ascii wide
        $ip_4 = "62.109.0.189" ascii wide

condition: 
         pe.is_pe and
         3 of ($u_*) and
         3 of ($d_*) and 
         1 of ($ip_*)  
}

