import "hash"
import "pe"

rule CaddyWiper
{
    meta:
        description = "Detect CaddyWiper"
        author = "blade391off"
        date = "2026-09-15"
        category = "Wiper"
        threat_actor = "Sandworm"

    strings:
        $api_domain = "DsRoleGetPrimaryDomainInformation" ascii wide
        $api_device = "DeviceIoControl" ascii wide
        $physical_drive = "\\\\.\\PHYSICALDRIVE" ascii wide
        $users_path = "\\Users" ascii wide
        $take_ownership = "SeTakeOwnershipPrivilege" ascii wide
        $drive_layout = "IOCTL_DISK_SET_DRIVE_LAYOUT_EX" ascii wide
        $caddy_name = "caddy1.exe" ascii wide

    condition:
        hash.sha256(0, filesize) == "a294620543334a721a2ae8eaaf9680a0786f4b9a216d75b55cfd28f39e9430ea"
        or
        (
            pe.is_pe
            and
            4 of ($api_*)
            and
            2 of ($physical_drive, $users_path, $take_ownership, $drive_layout, $caddy_name)
        )
}
