import "pe"

rule Generic_Loader
{
    meta:
        author = "blade391off"
        description = "Detects Generic Loader"
        version = "1.5"
        date = "2026-08-20"

    strings:
        $download_1 = "URLDownloadToFile" ascii wide nocase
        $download_2 = "InternetOpenUrl" ascii wide nocase
        $download_3 = "WinHttpOpenRequest" ascii wide nocase
        $download_4 = "WinHttpSendRequest" ascii wide nocase

        $exec_1 = "CreateProcessW" ascii wide
        $exec_2 = "ShellExecuteExW" ascii wide
        $exec_3 = "WinExec" ascii wide nocase

        $temp_1 = "\\AppData\\Local\\Temp\\" ascii wide nocase
        $temp_2 = "C:\\Windows\\Temp\\" ascii wide nocase

        $powershell = "powershell.exe" ascii wide nocase
        $cmd = "cmd.exe /c" ascii wide nocase
        $rundll32 = "rundll32.exe" ascii wide nocase

        $bypass = "-ExecutionPolicy Bypass" ascii wide nocase
        $hidden_1 = "-WindowStyle Hidden" ascii wide nocase
        $hidden_2 = " -w hidden " ascii wide nocase
        $nop = " -nop " ascii wide nocase
        $download_string = "DownloadString" ascii wide nocase
        $download_file = "DownloadFile" ascii wide nocase

        $run = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii wide nocase
        $runonce = "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce" ascii wide nocase

    condition:
        pe.is_pe and
        filesize < 15MB and
        (
            (
                2 of ($download_*) and
                1 of ($exec_*) and
                1 of ($temp_*)
            )
            or
            (
                $powershell and
                2 of ($bypass, $hidden_1, $hidden_2, $nop, $download_string, $download_file) and
                1 of ($temp_*)
            )
            or
            (
                1 of ($powershell, $cmd, $rundll32) and
                2 of ($download_*) and
                1 of ($exec_*)
            )
            or
            (
                1 of ($run, $runonce) and
                1 of ($powershell, $cmd, $rundll32) and
                1 of ($download_*)
            )
        )
}
