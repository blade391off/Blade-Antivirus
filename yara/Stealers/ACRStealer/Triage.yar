import "pe"

rule ACRStealer
{
          meta:
             author = "blade391off"
             description = "Detect ACRStealer" 
             category = "Stealer"
             threat_actor = "MaaS(Unknown)"

strings:

$dropped_1 = "o/41/tokens.txt"
$dropped_2 = "g/screen/screen.bmp"


$api_1 = "ConvertThreadToFiber"
$api_2 = "CreateFiber"
$api_3 = "SwitchToFiber"


condition: 
          pe.is_pe and
          (2 of ($dropped_*) and 1 of ($api_*))
          or
          pe.is_pe and
          (1 of ($dropped_*) and 3 of ($api_*))  
}


