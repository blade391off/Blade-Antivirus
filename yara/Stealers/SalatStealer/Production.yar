import "pe"

rule SalatStealer
{
        meta: 
           author = "blade391off"
           description = "Detect SalatStealer"
           category = "Stealer"
           date = "31.10.2026"
           threat_actor = "NyashTeam and Kapchenka"
           

strings:
             
        $go_lib1 = "github.com/tetratelabs/wazero" ascii wide 
        $go_lib3 = "github.com/ncruces/go-sqlite3" ascii wide 
        $go_lib4 = "github.com/capnspacehook/taskmaster" ascii wide
        $go_lib5 = "github.com/gorilla/websocket" ascii wide 

        
       
        $sql_pass1 = "SELECT item1, item2 FROM metaData WHERE id = 'password'" ascii wide 
        $sql_pass2 = "SELECT origin_url, action_url, username_value, password_value, date_created FROM logins" ascii wide
        $sql_pass3 = "SELECT origin_url, username_element, username_value, password_element, password_value, signon_realm FROM logins" ascii wide
        $sql_cookie = "SELECT name,encrypted_value,host_key,path,expires_utc FROM cookies WHERE length(encrypted_value) > 0" ascii wide
        $sql_sys    = "SELECT LogonId, StartTime, LogonType FROM Win32_LogonSession WHERE LogonType=2" ascii wide
      
        $path_1 = "/sa1at/" ascii wide nocase
        $path_2 = "/client/addclient" ascii wide nocase
        $path_3 = "/alive.php" ascii wide

        
        $c2_1 = "salat.cn" ascii wide nocase
        $c2_2 = "salator.es" ascii wide nocase
        $c2_3 = "salator.ru" ascii wide nocase
        $c2_4 = "websalat.top" ascii wide nocase
        $c2_5 = "wrat.in" ascii wide nocase
        $c2_6 = "sa1at.ru" ascii wide nocase
        $c2_7 = "webr.at" ascii wide nocase
        $c2_8 = "webrat.su" ascii wide nocase
        $c2_9 = "webrat.in" ascii wide nocase
        $c2_10 = "webrat.top" ascii wide nocase
        $c2_11 = "sa1atik.cn" ascii wide nocase

condition:

             pe.is_pe and
             4 of ($go_*) and 
             3 of ($sql_*) and
             3 of ($path_*) and
             4 of ($c2_*)
}


