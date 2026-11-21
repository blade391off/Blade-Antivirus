import "hash"
import "pe"

rule Miner
{
    meta:
        description = "Detects the miner sample and its distinctive PE and malware artifacts"
        author = "blade391off"
        reference = "ANY.RUN"
        threat = "Crypto malware"
        sample_sha256 = "EC61768C0A7DA9650F8662AE0918FC48DC2BED6B4A97F277CEB5FDD4B1EF65F4"
        sample_md5 = "80402E15A81E4F513980857455EB5A9C"
        sample_sha1 = "7F7937F7062CBBDF1C6FD3CA791124889A8C84F6"

    strings:
        $service = "RemoteSSDPClient" ascii wide nocase
        $service_dll = "RemoteSSDPClient.dll" ascii wide nocase
        $rdpckm = "rdpckm.dat" ascii wide nocase
        $netsvcs = "AeLookupSvc" ascii wide nocase
        $network_ip = "185.128.24.101" ascii wide
        $install = "install.php" ascii wide nocase
        $task_upnp = "\\Microsoft\\Windows\\UPnP\\" ascii wide nocase
        $task_tcpip = "\\Microsoft\\Windows\\Tcpip\\" ascii wide nocase
        $task_time = "\\Microsoft\\Windows\\Time Synchronization\\" ascii wide nocase
        $proxy_enable = "ProxyEnable" ascii wide nocase
        $zone_map = "ZoneMap" ascii wide nocase
        $unc_intranet = "UNCAsIntranet" ascii wide nocase
        $auto_detect = "AutoDetect" ascii wide nocase
        $self_delete = "cmd.exe" ascii wide nocase
        $netstat = "NETSTAT.EXE" ascii wide nocase
        $ping = "PING.EXE" ascii wide nocase
        $schtasks = "schtasks.exe" ascii wide nocase

    condition:
        hash.sha256(0, filesize) == "ec61768c0a7da9650f8662ae0918fc48dc2bed6b4a97f277ceb5fdd4b1ef65f4"
        or
        (
            uint16(0) == 0x5A4D
            and pe.is_pe
            and pe.machine == 0x014c
            and pe.number_of_sections == 5
            and pe.subsystem == 3
            and pe.entry_point == 0x65f7
            and
            (
                2 of ($service*)
                or ($network_ip and $install)
                or 2 of ($task_*)
                or ($proxy_enable or $zone_map or $unc_intranet or $auto_detect)
                or $self_delete
                or $rdpckm
                or $netsvcs
                or 1 of ($netstat, $ping, $schtasks)
            )
        )
}
