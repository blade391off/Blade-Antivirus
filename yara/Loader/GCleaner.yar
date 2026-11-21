import "pe"
import "hash"

rule gcleaner
{
    meta:
        author = "blade391off"
        description = "Detect GCleaner"
        family = "GCleaner"
        type = "malware_loader"
        version = "2.2"
        date = "2026-08-20"
        references = "ANY.RUN"

    strings:
        $gc_name = "GCLEANER" ascii nocase
        $gc_process = "svchost015.exe" ascii wide nocase

        $recovery_setup = "Recovery_Setup.exe" ascii wide nocase
        $flscover = "FLSCover" ascii wide nocase
        $rec528 = "Rec528" ascii wide nocase
        $rec528_exe = "Rec528.exe" ascii wide nocase
        $uninstaller = "unins000.exe" ascii wide nocase

        $inno_setup = "Inno Setup" ascii wide nocase
        $inno_uninstall = "InnoUninstall" ascii wide nocase
        $borland = "Borland" ascii wide nocase
        $delphi = "Delphi" ascii wide nocase

        $computer_name = "ComputerName" ascii wide nocase
        $machine_guid = "MachineGuid" ascii wide nocase
        $keyboard_layout = "Keyboard Layout\\Preload" ascii wide nocase
        $internet_explorer = "Internet Explorer" ascii wide nocase
        $proxy = "ProxyServer" ascii wide nocase
        $proxy_enable = "ProxyEnable" ascii wide nocase
        $product_name = "ProductName" ascii wide nocase
        $current_build = "CurrentBuild" ascii wide nocase

        $c2_ip_1 = "185.243.98.19" ascii
        $c2_uri_1 = "/success?substr=mixsix&s=three&sub=none" ascii
        $c2_ip_2 = "94.154.35.25" ascii
        $c2_uri_2 = "/di9ku38f/index.php" ascii
        $download_1 = "/files/8434554557/QKTi8Lo.exe" ascii

        $lumma = "Lumma" ascii wide nocase
        $rhadamanthys = "Rhadamanthys" ascii wide nocase
        $amadey = "Amadey" ascii wide nocase
        $remcos = "Remcos" ascii wide nocase
        $stealc = "STEALC" ascii wide nocase
        $vidar = "VIDAR" ascii wide nocase
        $purelogs = "PURELOGS" ascii wide nocase
        $purecrypter = "PURECRYPTER" ascii wide nocase
        $xmrig = "XMRIG" ascii wide nocase

        $amadey_version = "5.55" ascii
        $amadey_dropdir = "96a319e745" ascii
        $amadey_dropname = "Srxelqcif.exe" ascii
        $amadey_cred = "cred.dll" ascii wide nocase
        $amadey_clip = "clip.dll" ascii wide nocase
        $amadey_plugins = "/Plugins/" ascii wide nocase
        $amadey_video = "VideoID" ascii wide nocase

        $remcos_mutex = "REMCOS" ascii wide nocase
        $remcos_licence = "licence" ascii wide nocase
        $remcos_uid = "UID" ascii wide nocase

        $run = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii wide nocase
        $runonce = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce" ascii wide nocase
        $services = "SYSTEM\\CurrentControlSet\\Services\\" ascii wide nocase

        $powershell = "powershell.exe" ascii wide nocase
        $encoded = "-EncodedCommand" ascii wide nocase
        $hidden = "-WindowStyle Hidden" ascii wide nocase
        $rundll32 = "rundll32.exe" ascii wide nocase
        $taskkill = "taskkill /f /im" ascii wide nocase

        $defender = "WinDefender" ascii wide nocase
        $mp_pref = "Add-MpPreference" ascii wide nocase
        $exclusion_path = "ExclusionPath" ascii wide nocase
        $exclusion_extension = "ExclusionExtension" ascii wide nocase

        $screenconnect_msi = "ScreenConnect.ClientSetup.msi" ascii wide nocase
        $screenconnect_service = "ScreenConnect.ClientService.exe" ascii wide nocase
        $connectwise = "CONNECTWISE" ascii wide nocase

    condition:
        pe.is_pe and
        filesize < 15MB and
        (
            hash.sha256(0, filesize) == "e04a299110a591edac010a57b9df1457433864e9642b6126951614d1af20cb59" or
            hash.sha256(0, filesize) == "0829c26f3453be9269c2e48dd3393d7f5e1dc843e4ce309da7704b5e6ac3aa21" or
            hash.sha256(0, filesize) == "e647a6c94251db1a474dd9b4ed8dbe52c3e53f34f827bc56ae745cb7711b3d74" or
            hash.sha256(0, filesize) == "8b0570c9ee5a7d5d1eeb5bd226d9faf598b152a83c044975cb2de076453d425f" or
            hash.sha256(0, filesize) == "fd0941cee9b3f2e0c9e3ce51def41ae9370c1a1ffc92756d5cb48ce99f190a78" or

            (
                $gc_process and
                (
                    1 of ($computer_name, $machine_guid, $keyboard_layout) and
                    1 of ($proxy, $proxy_enable, $internet_explorer)
                )
            ) or

            (
                $gc_name and
                (
                    $gc_process or
                    2 of ($computer_name, $machine_guid, $keyboard_layout,
                          $product_name, $current_build)
                )
            ) or

            (
                2 of ($recovery_setup, $flscover, $rec528, $rec528_exe, $uninstaller) and
                1 of ($inno_setup, $inno_uninstall, $borland, $delphi)
            ) or

            (
                2 of ($c2_ip_1, $c2_uri_1, $c2_ip_2, $c2_uri_2, $download_1)
            ) or

            (
                2 of ($computer_name, $machine_guid, $keyboard_layout,
                      $product_name, $current_build) and
                2 of ($proxy, $proxy_enable, $internet_explorer)
            ) or

            (
                $gc_process and
                1 of ($lumma, $rhadamanthys, $amadey, $remcos,
                      $stealc, $vidar, $purelogs, $purecrypter)
            ) or

            (
                $gc_name and
                1 of ($lumma, $rhadamanthys, $amadey, $remcos)
            ) or

            (
                $gc_process and
                2 of ($defender, $mp_pref, $exclusion_path, $exclusion_extension)
            ) or

            (
                $gc_process and
                2 of ($powershell, $encoded, $hidden, $rundll32,
                      $taskkill, $run, $runonce, $services)
            ) or

            (
                $gc_process and
                2 of ($screenconnect_msi, $screenconnect_service, $connectwise)
            ) or

            (
                1 of ($amadey_version, $amadey_dropdir, $amadey_dropname,
                      $amadey_cred, $amadey_clip, $amadey_plugins,
                      $amadey_video, $remcos_mutex, $remcos_licence,
                      $remcos_uid, $xmrig) and
                1 of ($gc_name, $gc_process)
            )
        )
}
