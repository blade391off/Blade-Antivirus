import "pe"

rule Target_Family_PUP_HighConfidence_PE
{
    meta:
        author = "blade391off"
        description = "PUP detect"
        date = "2026-08-17"
        threat_level = "medium"
        detection_type = "static_pe"

    strings:
        $task_1 = "schtasks.exe" ascii wide nocase
        $task_2 = "schtasks /create" ascii wide nocase
        $task_3 = "Schedule.Service" ascii wide nocase
        $task_4 = "IRegisteredTask" ascii wide nocase
        $task_5 = "ITaskService" ascii wide nocase
        $task_6 = "\\Microsoft\\Windows\\Tasks\\" ascii wide nocase

        $download_1 = "URLDownloadToFileW" ascii
        $download_2 = "URLDownloadToFileA" ascii
        $download_3 = "WinHttpOpenRequest" ascii
        $download_4 = "WinHttpSendRequest" ascii
        $download_5 = "InternetOpenUrlW" ascii
        $download_6 = "InternetOpenUrlA" ascii

        $install_1 = "msiexec.exe" ascii wide nocase
        $install_2 = "/quiet" ascii wide nocase
        $install_3 = "/silent" ascii wide nocase
        $install_4 = "/verysilent" ascii wide nocase

        $advert_1 = "adware" ascii wide nocase
        $advert_2 = "advertisement" ascii wide nocase
        $advert_3 = "sponsored" ascii wide nocase
        $advert_4 = "advertising" ascii wide nocase

    condition:
        pe.is_pe
        and
        filesize < 50MB
        and
        (
            (
                2 of ($task_*)
                and
                (
                    pe.imports("ADVAPI32.dll", "RegCreateKeyExW") or
                    pe.imports("ADVAPI32.dll", "RegSetValueExW") or
                    pe.imports("KERNEL32.dll", "CreateProcessW") or
                    pe.imports("SHELL32.dll", "ShellExecuteW")
                )
            )
            or
            (
                2 of ($download_*)
                and
                (
                    pe.imports("URLMON.dll", "URLDownloadToFileW") or
                    pe.imports("WINHTTP.dll", "WinHttpOpenRequest") or
                    pe.imports("WININET.dll", "InternetOpenUrlW")
                )
                and
                1 of ($install_*)
            )
            or
            (
                2 of ($advert_*)
                and
                (
                    pe.imports("USER32.dll", "MessageBoxW") or
                    pe.imports("USER32.dll", "CreateWindowExW")
                )
            )
        )
}
