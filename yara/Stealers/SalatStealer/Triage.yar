import "pe"

rule SalatStealer
{
        meta: 
          author = "blade391off"
          description = "Fast detect SalatStealer with network IOC"
          category = "Stealer"
          threat_actor = "NyashTeam and Kapchenka"

strings:

$mal_1 = "https://salat.cn/sa1at/" ascii wide 
$mal_2 = "https://salator.es/sa1at/" ascii wide 
$mal_3 = "https://salator.ru/sa1at/" ascii wide 
$mal_4 = "https://websalat.top/sa1at/" ascii wide 
$mal_5 = "https://wrat.in:992/sa1at/" ascii wide


$ip_1 = "172.67.194.254"
$ip_2 = "104.21.60.88"

condition:

        pe.is_pe and 
        2 of ($mal_*) and 
        1 of ($ip_*)
}
