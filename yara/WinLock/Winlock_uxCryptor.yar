import "pe"
import "hash"

rule WinLocker_Winlock_uxCryptor
{
meta:
author = "blade391off"
date = "2026-08-18"
version = "1.4"
description = "Detect UxCryptor"
family = "WinLocker"
category = "Ransomware / ScreenLocker"
threat_level = "critical"
confidence = "high"
reference = "ANY.RUN task 99bf97f2-6c23-4721-9e8c-8d722b74e7ac"

strings:
    $ux_cryptor_1 = "ux-cryptor.exe" ascii wide nocase
    $ux_cryptor_2 = "crypt0rsx.exe" ascii wide nocase
    $ux_cryptor_3 = "AWindowsService.exe" ascii wide nocase
    $ux_cryptor_4 = "windowsx-c.exe" ascii wide nocase
    $ux_cryptor_5 = "_default64.exe" ascii wide nocase
    $ux_cryptor_6 = "WIN32_1" ascii wide nocase
    $ux_cryptor_7 = "WIN32_2" ascii wide nocase
    $ux_cryptor_8 = "WIN32_3" ascii wide nocase
    $ux_cryptor_9 = "WIN32_4" ascii wide nocase
    $ux_cryptor_10 = "WIN32_5" ascii wide nocase
    $ux_cryptor_11 = "WIN32_6" ascii wide nocase
    $ux_cryptor_12 = "WIN32_7" ascii wide nocase
    $ux_cryptor_13 = "WIN32_8" ascii wide nocase

    $locker_file = "info-Locker.txt" ascii wide nocase
    $unlocker_file = ".ux-cryptobytes" ascii wide nocase

    $encrypted_msg_1 = "Your files are encrypted" ascii wide nocase
    $encrypted_msg_2 = "Ooops!" ascii wide nocase
    $encrypted_msg_3 = "Введите код разблокировки" wide
    $encrypted_msg_4 = "Ваши файлы зашифрованы" wide

    $run_key = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii wide nocase
    $run_wininstaller = "WindowsInstaller" ascii wide nocase
    $run_edgeupdate = "MSEdgeUpdateX" ascii wide nocase

    $cmd = "cmd.exe" ascii wide nocase
    $attrib = "attrib" ascii wide nocase
    $taskkill = "taskkill.exe" ascii wide nocase

    $desktop = "%userprofile%\\desktop" ascii wide nocase

    $mscoree = "mscoree.dll" ascii wide nocase
    $lc_exe = "lc.exe" ascii wide nocase

condition:
    (
        uint16(0) == 0x5A4D
        and filesize <= 20MB
        and
        (
            hash.sha256(0, filesize) == "d3f47cd85c525a0c3ed855949bf27023c27b24c51d388166d72d4fa8cae4c2f5"
            or hash.sha256(0, filesize) == "593e60cc30ae0789448547195af77f550387f6648d45847ea244dd0dd7abf03d"
            or hash.sha256(0, filesize) == "ead58c483cb20bcd57464f8a4929079539d634f469b213054bf737d227c026dc"
            or hash.sha256(0, filesize) == "7587e29919a56b6f94675e49208e1ae908bcab09363734d846502c3b4ad54326"
            or hash.sha256(0, filesize) == "2a0aa0763fdef9c38c5dd4d50703f0c7e27f4903c139804ec75e55f8388139ae"
            or hash.sha256(0, filesize) == "9b2c8b8c4cec301c4303f58ca4e8b261d516f10feb24573b092dfccc263baea4"
            or hash.sha256(0, filesize) == "43eef3b68ebaab3efbe15eb3046281e380aa78003a0eda8757a9e44f6a59ec7f"
            or hash.sha256(0, filesize) == "e17cd94c08fc0e001a49f43a0801cea4625fb9aee211b6dfebebec446c21f460"
            or hash.sha256(0, filesize) == "6a24bf4ae4359cb9c5cbe6a0ad3fe150dd7380313dc31587c4c5e2564c50274a"
            or hash.sha256(0, filesize) == "cec9df2d0292931147c824203ac9a594088e91ca04ea8cc128b7dc9dc42ae805"
            or hash.sha256(0, filesize) == "e49dc5724adee8f30ff25f0bb587e318f4f3d4c0f051866b437c831e7253b988"
        )
    )
    or
    (
        uint16(0) == 0x5A4D
        and filesize <= 20MB
        and
        (
            $mscoree
            or pe.number_of_sections <= 5
        )
        and
        (
            (
                $run_key
                and
                (
                    $run_wininstaller
                    or $run_edgeupdate
                    or ($ux_cryptor_1 and $ux_cryptor_2)
                    or ($ux_cryptor_1 and $ux_cryptor_3)
                    or ($ux_cryptor_1 and $ux_cryptor_4)
                    or ($ux_cryptor_1 and $ux_cryptor_5)
                    or ($ux_cryptor_2 and $ux_cryptor_3)
                    or ($ux_cryptor_2 and $ux_cryptor_4)
                    or ($ux_cryptor_2 and $ux_cryptor_5)
                    or ($ux_cryptor_3 and $ux_cryptor_4)
                    or ($ux_cryptor_3 and $ux_cryptor_5)
                    or ($ux_cryptor_4 and $ux_cryptor_5)
                )
            )
            or
            (
                (
                    ($locker_file and $unlocker_file)
                    or ($locker_file and $encrypted_msg_1)
                    or ($locker_file and $encrypted_msg_2)
                    or ($locker_file and $encrypted_msg_3)
                    or ($locker_file and $encrypted_msg_4)
                    or ($unlocker_file and $encrypted_msg_1)
                    or ($unlocker_file and $encrypted_msg_2)
                    or ($unlocker_file and $encrypted_msg_3)
                    or ($unlocker_file and $encrypted_msg_4)
                    or ($encrypted_msg_1 and $encrypted_msg_2)
                    or ($encrypted_msg_1 and $encrypted_msg_3)
                    or ($encrypted_msg_1 and $encrypted_msg_4)
                    or ($encrypted_msg_2 and $encrypted_msg_3)
                    or ($encrypted_msg_2 and $encrypted_msg_4)
                    or ($encrypted_msg_3 and $encrypted_msg_4)
                )
                and
                (
                    $cmd
                    or $attrib
                    or $taskkill
                )
            )
            or
            (
                (
                    $ux_cryptor_1
                    and $ux_cryptor_2
                    and $ux_cryptor_3
                )
                or
                (
                    $ux_cryptor_1
                    and $ux_cryptor_2
                    and $ux_cryptor_4
                )
                or
                (
                    $ux_cryptor_1
                    and $ux_cryptor_2
                    and $ux_cryptor_5
                )
                or
                (
                    $ux_cryptor_1
                    and $ux_cryptor_3
                    and $ux_cryptor_4
                )
                or
                (
                    $ux_cryptor_1
                    and $ux_cryptor_3
                    and $ux_cryptor_5
                )
                or
                (
                    $ux_cryptor_1
                    and $ux_cryptor_4
                    and $ux_cryptor_5
                )
                or
                (
                    $ux_cryptor_2
                    and $ux_cryptor_3
                    and $ux_cryptor_4
                )
                or
                (
                    $ux_cryptor_2
                    and $ux_cryptor_3
                    and $ux_cryptor_5
                )
                or
                (
                    $ux_cryptor_2
                    and $ux_cryptor_4
                    and $ux_cryptor_5
                )
                or
                (
                    $ux_cryptor_3
                    and $ux_cryptor_4
                    and $ux_cryptor_5
                )
            )
            or
            (
                $cmd
                and $attrib
                and
                (
                    $locker_file
                    or $unlocker_file
                    or $encrypted_msg_1
                    or $encrypted_msg_2
                    or $encrypted_msg_3
                    or $encrypted_msg_4
                )
            )
            or
            (
                $desktop
                and
                (
                    $locker_file
                    or $unlocker_file
                    or $encrypted_msg_1
                    or $encrypted_msg_2
                    or $encrypted_msg_3
                    or $encrypted_msg_4
                )
            )
            or ($lc_exe and ($locker_file or $unlocker_file))
            or
            (
                3 of (
                    $ux_cryptor_6,
                    $ux_cryptor_7,
                    $ux_cryptor_8,
                    $ux_cryptor_9,
                    $ux_cryptor_10,
                    $ux_cryptor_11,
                    $ux_cryptor_12,
                    $ux_cryptor_13
                )
            )
        )
    )
}
