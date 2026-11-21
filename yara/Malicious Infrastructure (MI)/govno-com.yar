import "pe"

rule Detect_govno_com
{
    meta:
        description = "Detect govno.com Malicious Infrastructure"
        author = "blade391off"
        date = "2026-09-04"
        category = "MI - Malicious Infrastructure"
        threat_actor = "Unknown"

    strings:
        $domain = "govno.com" ascii wide nocase
        $domain_dot = "govno.com." ascii wide nocase
        $ip = "157.230.161.221" ascii wide

        $wscript = "wscript.exe" ascii wide nocase
        $cscript = "cscript.exe" ascii wide nocase
        $cmd = "cmd.exe" ascii wide nocase

        $taskkill = "taskkill.exe" ascii wide nocase
        $takeown = "takeown.exe" ascii wide nocase
        $icacls = "icacls.exe" ascii wide nocase

        $run = "CurrentVersion\\Run" ascii wide nocase
        $runonce = "CurrentVersion\\RunOnce" ascii wide nocase
        $winlogon = "Winlogon" ascii wide nocase
        $userinit = "Userinit" ascii wide nocase

        $defender = "Windows Defender" ascii wide nocase
        $windefend = "WinDefend" ascii wide nocase
        $disable_defender = "DisableAntiSpyware" ascii wide nocase
        $security_health = "SecurityHealthService" ascii wide nocase

        $wscript_shell = "WScript.Shell" ascii wide nocase
        $shell_application = "Shell.Application" ascii wide nocase

        $vbs = ".vbs" ascii wide nocase
        $bat = ".bat" ascii wide nocase

        $schtasks = "schtasks" ascii wide nocase
        $task_scheduler = "Task Scheduler" ascii wide nocase

        $shutdown = "shutdown.exe" ascii wide nocase

    condition:
        uint16(0) == 0x5A4D and
        (
            (1 of ($domain, $domain_dot) and $ip)
            or
            (
                1 of ($domain, $domain_dot) and
                2 of (
                    $wscript,
                    $cscript,
                    $cmd,
                    $taskkill,
                    $takeown,
                    $icacls,
                    $run,
                    $runonce,
                    $winlogon,
                    $userinit,
                    $defender,
                    $windefend,
                    $disable_defender,
                    $vbs,
                    $bat,
                    $wscript_shell,
                    $schtasks,
                    $task_scheduler
                )
            )
            or
            (
                2 of ($taskkill, $takeown, $icacls) and
                2 of ($defender, $windefend, $disable_defender, $security_health) and
                1 of ($run, $runonce, $winlogon, $userinit, $schtasks, $task_scheduler)
            )
            or
            (
                2 of ($wscript, $cscript, $vbs, $bat, $wscript_shell, $shell_application) and
                2 of ($taskkill, $takeown, $icacls, $schtasks, $task_scheduler, $shutdown)
            )
        )
}
