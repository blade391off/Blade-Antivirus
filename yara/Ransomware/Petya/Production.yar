rule Production_Petya_Family_Blade391off
{
    meta:
        author = "blade391off"
        description = "Production grade rule with extensive signature base covering Petya, Mischa, NotPetya, ExPetr, and GoldenEye variants"
        threat_level = "Critical"
        date = "2026-08-11"

    strings:
        $petya_str_001 = "Your computer's hard drive has been encrypted" ascii fullword
        $petya_str_002 = "http://petya" ascii fullword
        $petya_str_003 = "Please enter the decryption key here:" ascii fullword
        $petya_str_004 = "The encryption process is irreversible" ascii fullword
        $petya_str_005 = "Do not power off or restart your PC" ascii fullword
        $petya_str_006 = "All your files are lost if you don't pay" ascii fullword
        $petya_str_007 = "Tor Browser" ascii fullword
        $petya_str_008 = "petya3joxbe6m6w5.onion" ascii fullword
        $petya_str_009 = "petya5scwlkf6w.onion" ascii fullword
        $petya_str_010 = "petya6shzlf3w.onion" ascii fullword
        $petya_str_011 = "Incorrect key! Please try again." ascii fullword
        $petya_str_012 = "Your personal decryption code:" ascii fullword
        $petya_str_013 = "Bitcoin wallet address" ascii fullword
        $petya_str_014 = "Send exactly the specified amount" ascii fullword
        $petya_str_015 = "A key verification failed" ascii fullword
        $petya_str_016 = "sector checksum mismatch" ascii fullword
        $petya_str_017 = "Loading sectors..." ascii fullword
        $petya_str_018 = "Repairing file system anomalies" ascii fullword
        $petya_str_019 = "Decryption successfully finished!" ascii fullword
        $petya_str_020 = "Press any key to reboot" ascii fullword

        $mischa_str_021 = "YOUR FILES ARE ENCRYPTED" ascii fullword
        $mischa_str_022 = "YOUR PERSONAL IDENTIFICATION CODE" ascii fullword
        $mischa_str_023 = "mischapasi" ascii fullword
        $mischa_str_024 = "mischapage" ascii fullword
        $mischa_str_025 = "YOUR_FILES_ARE_ENCRYPTED.TXT" ascii wide fullword
        $mischa_str_026 = "YOUR_FILES_ARE_ENCRYPTED.HTML" ascii wide fullword
        $mischa_str_027 = "mischa5xbe6m6w5.onion" ascii fullword
        $mischa_str_028 = "Payment wizard" ascii fullword
        $mischa_str_029 = "Wizard instructions" ascii fullword
        $mischa_str_030 = "File locker dynamic library" ascii fullword
        $mischa_str_031 = "Cryptographic execution failed" ascii fullword
        $mischa_str_032 = "Cannot generate keypair" ascii fullword
        $mischa_str_033 = "AES-256 payload generation" ascii fullword
        $mischa_str_034 = "RSA public parameter mismatch" ascii fullword
        $mischa_str_035 = "Extensions to encrypt:" ascii fullword
        $mischa_str_036 = ".msh" ascii fullword
        $mischa_str_037 = ".mischa" ascii fullword
        $mischa_str_038 = "Failed to parse drive structure" ascii fullword
        $mischa_str_039 = "Local disk scanning initialized" ascii fullword
        $mischa_str_040 = "Excluding system directories from wipe" ascii fullword

        $notpetya_str_041 = "wowsmith123456" ascii fullword
        $notpetya_str_042 = "Send $300 worth of Bitcoin to following address" ascii fullword
        $notpetya_str_043 = "wowsmith123456@posteo.net" ascii fullword
        $notpetya_str_044 = "1Mz7153HMuxXTuR2R1t78mGSdzaAtNbBWX" ascii fullword
        $notpetya_str_045 = "If you see this text, then your files are no longer accessible" ascii fullword
        $notpetya_str_046 = "Installation key:" ascii fullword
        $notpetya_str_047 = "Please do not waste your time" ascii fullword
        $notpetya_str_048 = "No one can recover your files without" ascii fullword
        $notpetya_str_049 = "perfc.dat" ascii wide fullword
        $notpetya_str_050 = "perfc" ascii wide fullword
        $notpetya_str_051 = "dllhost.exe" ascii wide fullword
        $notpetya_str_052 = "OpenProcessToken failed" ascii fullword
        $notpetya_str_053 = "LookupPrivilegeValue failed" ascii fullword
        $notpetya_str_054 = "AdjustTokenPrivileges failed" ascii fullword
        $notpetya_str_055 = "GetProcAddress failed" ascii fullword
        $notpetya_str_056 = "LoadLibraryA failed" ascii fullword
        $notpetya_str_057 = "CreateProcessW failed" ascii fullword
        $notpetya_str_058 = "CloseHandle failed" ascii fullword
        $notpetya_str_059 = "WriteProcessMemory failed" ascii fullword
        $notpetya_str_060 = "VirtualAllocEx failed" ascii fullword

        $goldeneye_str_061 = "GoldenEye" ascii fullword
        $goldeneye_str_062 = "YOUR_FILES_ARE_ENCRYPTED.TXT" ascii wide fullword
        $goldeneye_str_063 = "goldeneye5xbe6m.onion" ascii fullword
        $goldeneye_str_064 = "Your personal decryption key is ready" ascii fullword
        $goldeneye_str_065 = "Enter personal key:" ascii fullword
        $goldeneye_str_066 = "Fatal error during system allocation" ascii fullword
        $goldeneye_str_067 = "XOR key computation failed" ascii fullword
        $goldeneye_str_068 = "Salsa20 core initialization" ascii fullword
        $goldeneye_str_069 = "MFT primary record locked" ascii fullword
        $goldeneye_str_070 = "Master File Table compression error" ascii fullword
        $goldeneye_str_071 = "Encrypted extensions tracking" ascii fullword
        $goldeneye_str_072 = "Yellow interface loaded" ascii fullword
        $goldeneye_str_073 = "Reboot sequence targeted" ascii fullword
        $goldeneye_str_074 = "Force standard crash sequence" ascii fullword
        $goldeneye_str_075 = "Hard link modification active" ascii fullword
        $goldeneye_str_076 = "Volume shadow copies targeted" ascii fullword
        $goldeneye_str_077 = "VSS interface drop" ascii fullword
        $goldeneye_str_078 = "vssadmin delete shadows /all /quiet" ascii wide fullword
        $goldeneye_str_079 = "Execution parameters complete" ascii fullword
        $goldeneye_str_080 = "Main encryption loop active" ascii fullword

        $sys_str_081 = "wevtutil cl Setup" ascii wide fullword
        $sys_str_082 = "wevtutil cl System" ascii wide fullword
        $sys_str_083 = "wevtutil cl Security" ascii wide fullword
        $sys_str_084 = "wevtutil cl Application" ascii wide fullword
        $sys_str_085 = "shutdown.exe /r /f" ascii wide fullword
        $sys_str_086 = "shutdown /r /t 0" ascii wide fullword
        $sys_str_087 = "wmic /node:" ascii wide fullword
        $sys_str_088 = "process call create" ascii wide fullword
        $sys_str_089 = "SchTasks.exe" ascii wide fullword
        $sys_str_090 = "psexec.exe" ascii wide fullword
        $sys_str_091 = "SeDebugPrivilege" ascii fullword
        $sys_str_092 = "SeTcbPrivilege" ascii fullword
        $sys_str_093 = "SeTakeOwnershipPrivilege" ascii fullword
        $sys_str_094 = "SeBackupPrivilege" ascii fullword
        $sys_str_095 = "SeRestorePrivilege" ascii fullword
        $sys_str_096 = "SeShutdownPrivilege" ascii fullword
        $sys_str_097 = "SeAssignPrimaryTokenPrivilege" ascii fullword
        $sys_str_098 = "SeIncreaseQuotaPrivilege" ascii fullword
        $sys_str_099 = "\\*\\admin$" ascii wide fullword
        $sys_str_100 = "\\*\\C$\\Windows" ascii wide fullword

        $crypto_str_101 = "expand 32-byte k" ascii fullword
        $crypto_str_102 = "expand 16-byte k" ascii fullword
        $crypto_str_103 = "CryptAcquireContextW" ascii fullword
        $crypto_str_104 = "CryptGenRandom" ascii fullword
        $crypto_str_105 = "CryptReleaseContext" ascii fullword
        $crypto_str_106 = "CryptImportKey" ascii fullword
        $crypto_str_107 = "CryptEncrypt" ascii fullword
        $crypto_str_108 = "CryptDestroyKey" ascii fullword
        $crypto_str_109 = "BCryptGenRandom" ascii fullword
        $crypto_str_110 = "BCryptOpenAlgorithmProvider" ascii fullword
        $crypto_str_111 = "BCryptCloseAlgorithmProvider" ascii fullword
        $crypto_str_112 = "BCryptDecrypt" ascii fullword
        $crypto_str_113 = "BCryptEncrypt" ascii fullword
        $crypto_str_114 = "BCryptDestroyKey" ascii fullword
        $crypto_str_115 = "BCryptGenerateSymmetricKey" ascii fullword
        $crypto_str_116 = "CryptDeriveKey" ascii fullword
        $crypto_str_117 = "CryptCreateHash" ascii fullword
        $crypto_str_118 = "CryptHashData" ascii fullword
        $crypto_str_119 = "CryptGetHashParam" ascii fullword
        $crypto_str_120 = "CryptDestroyHash" ascii fullword

        $net_str_121 = "WNetOpenEnumW" ascii fullword
        $net_str_122 = "WNetEnumResourceW" ascii fullword
        $net_str_123 = "WNetCloseEnum" ascii fullword
        $net_str_124 = "WNetAddConnection2W" ascii fullword
        $net_str_125 = "NetShareEnum" ascii fullword
        $net_str_126 = "NetApiBufferFree" ascii fullword
        $net_str_127 = "GetIpNetTable" ascii fullword
        $net_str_128 = "GetExtendedTcpTable" ascii fullword
        $net_str_129 = "GetExtendedUdpTable" ascii fullword
        $net_str_130 = "GetAdaptersInfo" ascii fullword
        $net_str_131 = "GetAdaptersAddresses" ascii fullword
        $net_str_132 = "DnsQuery_W" ascii fullword
        $net_str_133 = "gethostbyname" ascii fullword
        $net_str_134 = "getaddrinfo" ascii fullword
        $net_str_135 = "freeaddrinfo" ascii fullword
        $net_str_136 = "WSAStartup" ascii fullword
        $net_str_137 = "WSACleanup" ascii fullword
        $net_str_138 = "socket" ascii fullword
        $net_str_139 = "connect" ascii fullword
        $net_str_140 = "send" ascii fullword

        $fs_str_141 = "FindFirstFileW" ascii fullword
        $fs_str_142 = "FindNextFileW" ascii fullword
        $fs_str_143 = "FindClose" ascii fullword
        $fs_str_144 = "GetDriveTypeW" ascii fullword
        $fs_str_145 = "GetLogicalDriveStringsW" ascii fullword
        $fs_str_146 = "CreateFileW" ascii fullword
        $fs_str_147 = "ReadFile" ascii fullword
        $fs_str_148 = "WriteFile" ascii fullword
        $fs_str_149 = "SetFilePointerEx" ascii fullword
        $fs_str_150 = "DeviceIoControl" ascii fullword
        $fs_str_151 = "GetFileSizeEx" ascii fullword
        $fs_str_152 = "GetFileAttributesW" ascii fullword
        $fs_str_153 = "SetFileAttributesW" ascii fullword
        $fs_str_154 = "MoveFileW" ascii fullword
        $fs_str_155 = "DeleteFileW" ascii fullword
        $fs_str_156 = "CreateDirectoryW" ascii fullword
        $fs_str_157 = "GetDiskFreeSpaceExW" ascii fullword
        $fs_str_158 = "GetVolumeInformationW" ascii fullword
        $fs_str_159 = "LockFileEx" ascii fullword
        $fs_str_160 = "UnlockFileEx" ascii fullword

        $hex_mbr_01 = { 8E D8 8E D0 BC 00 7C 89 E6 }
        $hex_mbr_02 = { FA B8 00 00 8E D0 BC 00 7C FB }
        $hex_mbr_03 = { B8 00 02 B8 01 02 BB 00 80 B9 01 00 CD 13 }
        $hex_mbr_04 = { B4 02 B0 22 ?? 00 ?? 02 ?? 00 ?? 80 }
        $hex_mbr_05 = { 2A C0 CD 13 72 ?? B8 01 03 BB 00 80 }
        $hex_mbr_06 = { B8 01 02 05 00 7C 8E D8 8E C0 }
        $hex_mbr_07 = { CD 10 32 ?? 32 ?? CD 16 }
        $hex_mbr_08 = { B4 0E B0 ?? B3 07 CD 10 EB ?? }
        $hex_mbr_09 = { 31 A0 31 B0 31 C0 31 D2 CD 13 }
        $hex_mbr_10 = { EA 00 7C 00 00 }

        $hex_kernel_01 = { 66 63 64 73 6B 2E 65 78 65 }
        $hex_kernel_02 = { 45 4E 54 45 52 20 4B 45 59 }
        $hex_kernel_03 = { 59 6F 75 72 20 63 6F 6D 70 75 74 65 72 }
        $hex_kernel_04 = { 68 61 72 64 20 64 72 69 76 65 }
        $hex_kernel_05 = { 65 6E 63 72 79 70 74 65 64 }
        $hex_kernel_06 = { 42 69 74 63 6F 69 6E }
        $hex_kernel_07 = { 6F 6E 69 6F 6E }
        $hex_kernel_08 = { 4B 65 79 20 76 65 72 69 66 69 63 61 74 69 6F 6E }
        $hex_kernel_09 = { 73 65 63 74 6F 72 20 63 68 65 63 6B 73 75 6D }
        $hex_kernel_10 = { 52 65 70 61 69 72 69 6E 67 20 66 69 6C 65 }

        $exploit_jet_01 = { 4A 45 54 5F 62 61 73 65 6E 61 6D 65 }
        $exploit_jet_02 = { 44 68 63 70 47 65 74 41 6C 6C 4F 70 74 69 6F 6E 44 65 66 69 6E 69 74 69 6F 6E 73 }

        $exploit_ms17_01 = { FF 53 44 4D 42 32 }
        $exploit_ms17_02 = { 00 00 00 50 46 45 32 00 }
        $exploit_ms17_03 = { FE 53 4D 42 40 00 }
        $exploit_ms17_04 = { 4D 53 31 37 2D 30 31 30 }

        $petya_perfc_dat = "C:\\Windows\\perfc.dat" ascii wide fullword

    condition:
        uint16(0) == 0x5A4D
        and filesize < 15MB
        and
        (
            $petya_perfc_dat
            or 5 of ($petya_str_*)
            or 5 of ($mischa_str_*)
            or 3 of ($notpetya_str_*)
            or 5 of ($goldeneye_str_*)
            or
            (
                3 of ($hex_mbr_*)
                and 2 of ($crypto_str_*)
            )
            or
            (
                3 of ($hex_kernel_*)
                and 2 of ($crypto_str_*)
            )
            or
            (
                2 of ($exploit_jet_*)
                and any of ($sys_str_*)
            )
            or
            (
                2 of ($exploit_ms17_*)
                and any of ($net_str_*)
            )
            or
            (
                10 of ($sys_str_*)
                and 10 of ($fs_str_*)
            )
            or
            (
                5 of ($crypto_str_*)
                and 5 of ($net_str_*)
                and 5 of ($fs_str_*)
            )
        )
}
