
rule hacktool_win_shellcode_donut_v1_x64
{
    meta:
        author = "threatintel@volexity.com"
        description = "Detection for donut loader shellcode version 1.0 x64"
        date = "2023-05-08"
        reference = "https://github.com/TheWover/donut/blob/v1.0/loader_exe_x64.h"
        donut_loader_version = "1.0"
        donut_bitness = "64"

    strings:
        $raw_bin = {48 89 5c 24 08 48 89 6c 24 10 48 89 74 24 18 57 41 56 41 57 48 81 ec 00 05 00 00 33 ff 48 8b d9 39 b9 38 02 00 00 0f 84 ce 00 00 00 4c 8b 41 28}
        $base64 = "\x48\x89\x5c\x24\x08\x48\x89\x6c\x24\x10\x48\x89\x74\x24\x18\x57\x41\x56\x41\x57\x48\x81\xec\x00\x05\x00\x00\x33\xff\x48\x8b\xd9\x39\xb9\x38\x02\x00\x00\x0f\x84\xce\x00\x00\x00\x4c\x8b\x41\x28" base64

    condition:
        any of them
}

rule hacktool_win_shellcode_donut_v1_x86
{
    meta:
        author = "threatintel@volexity.com"
        description = "Detection for donut loader shellcode version 1.0 x86"
        date = "2023-05-08"
        reference = "https://github.com/TheWover/donut/blob/v1.0/loader_exe_x86.h"
        donut_loader_version = "1.0"
        donut_bitness = "32"

    strings:
        $raw_bin = {81 ec d4 02 00 00 53 55 56 8b b4 24 e4 02 00 00 33 db 57 8b fb 39 9e 38 02 00 00 0f 84 ea 00 00 00 ff 76 2c ff 76 28 ff b6 8c 00 00 00 ff b6 88}
        $base64 = "\x81\xec\xd4\x02\x00\x00\x53\x55\x56\x8b\xb4\x24\xe4\x02\x00\x00\x33\xdb\x57\x8b\xfb\x39\x9e\x38\x02\x00\x00\x0f\x84\xea\x00\x00\x00\xff\x76\x2c\xff\x76\x28\xff\xb6\x8c\x00\x00\x00\xff\xb6\x88" base64

    condition:
        any of them
}

rule hacktool_win_shellcode_donut_v093_1_x64
{
    meta:
        author = "threatintel@volexity.com"
        description = "Detection for donut loader shellcode version 0.9.3 x64 variant 1"
        date = "2023-05-08"
        reference = "https://github.com/TheWover/donut/blob/v0.9.3/loader_exe_x64.h"
        donut_loader_version = "0.9.3_V1"
        donut_bitness = "64"

    strings:
        $raw_bin = {48 89 5c 24 08 48 89 6c 24 10 48 89 74 24 18 57 48 81 ec 00 05 00 00 33 ff 48 8b d9 48 39 b9 38 02 00 00 0f 84 c0 00 00 00 4c 8b 41 28 48 8b 91}
        $base64 = "\x48\x89\x5c\x24\x08\x48\x89\x6c\x24\x10\x48\x89\x74\x24\x18\x57\x48\x81\xec\x00\x05\x00\x00\x33\xff\x48\x8b\xd9\x48\x39\xb9\x38\x02\x00\x00\x0f\x84\xc0\x00\x00\x00\x4c\x8b\x41\x28\x48\x8b\x91" base64

    condition:
        any of them
}

rule hacktool_win_shellcode_donut_v093_2_x64
{
    meta:
        author = "threatintel@volexity.com"
        description = "Detection for donut loader shellcode version 0.9.3 x64 variant 2"
        date = "2023-05-08"
        reference = "https://github.com/TheWover/donut/blob/v0.9.3/loader_exe_x64.h"
        donut_loader_version = "0.9.3_V2"
        donut_bitness = "64"

    strings:
        $raw_bin = {55 48 81 EC 30 05 00 00 48 8D AC 24 80 00 00 00 48 89 8D C0 04 00 00 48 C7 85 A8 04 00 00 00 00 00 00 48 8B 85 C0 04 00 00 48 8B 80 38 02 00 00}
        $base64 = "\x55\x48\x81\xEC\x30\x05\x00\x00\x48\x8D\xAC\x24\x80\x00\x00\x00\x48\x89\x8D\xC0\x04\x00\x00\x48\xC7\x85\xA8\x04\x00\x00\x00\x00\x00\x00\x48\x8B\x85\xC0\x04\x00\x00\x48\x8B\x80\x38\x02\x00\x00" base64

    condition:
        any of them
}

rule hacktool_win_shellcode_donut_v093_1_x86
{
    meta:
        author = "threatintel@volexity.com"
        description = "Detection for donut loader shellcode version 0.9.3 x86 variant 1"
        date = "2023-05-08"
        reference = "https://github.com/TheWover/donut/blob/v0.9.3/loader_exe_x86.h"
        donut_loader_version = "0.9.3_V1"
        donut_bitness = "32"

    strings:
        $raw_bin = {81 ec cc 02 00 00 53 55 56 8b b4 24 dc 02 00 00 33 db 57 8b fb 8b 86 38 02 00 00 0b 86 3c 02 00 00 0f 84 d4 00 00 00 ff 76 2c ff 76 28 ff b6 8c}
        $base64 = "\x81\xec\xcc\x02\x00\x00\x53\x55\x56\x8b\xb4\x24\xdc\x02\x00\x00\x33\xdb\x57\x8b\xfb\x8b\x86\x38\x02\x00\x00\x0b\x86\x3c\x02\x00\x00\x0f\x84\xd4\x00\x00\x00\xff\x76\x2c\xff\x76\x28\xff\xb6\x8c" base64

    condition:
        any of them
}
rule hacktool_win_shellcode_donut_v093_2_x86
{
    meta:
        author = "threatintel@volexity.com"
        description = "Detection for donut loader shellcode version 0.9.3 x86 variant 2"
        date = "2023-05-08"
        reference = "https://github.com/TheWover/donut/blob/v0.9.3/loader_exe_x86.h"
        donut_loader_version = "0.9.3_V2"
        donut_bitness = "32"

    strings:
        $raw_bin = {55 89 E5 56 53 81 EC 10 03 00 00 C7 45 F4 00 00 00 00 8B 4D 08 8B 99 3C 02 00 00 8B 89 38 02 00 00 89 CE 83 F6 00 89 F0 80 F7 00 89 DA 09 D0 85}
        $base64 = "\x55\x89\xE5\x56\x53\x81\xEC\x10\x03\x00\x00\xC7\x45\xF4\x00\x00\x00\x00\x8B\x4D\x08\x8B\x99\x3C\x02\x00\x00\x8B\x89\x38\x02\x00\x00\x89\xCE\x83\xF6\x00\x89\xF0\x80\xF7\x00\x89\xDA\x09\xD0\x85" base64

    condition:
        any of them
}
rule hacktool_win_shellcode_donut_v093_3_x86
{
    meta:
        author = "threatintel@volexity.com"
        description = "Detection for donut loader shellcode version 0.9.3 x86 variant 3"
        date = "2023-05-08"
        reference = "https://github.com/TheWover/donut/blob/v0.9.3/loader_exe_x86.h"
        donut_loader_version = "0.9.3_V3"
        donut_bitness = "32"

    strings:
        $raw_bin = {55 89 E5 56 53 81 EC 10 03 00 00 C7 45 F4 00 00 00 00 8B 45 08 8B 90 3C 02 00 00 8B 80 38 02 00 00 89 C6 83 F6 00 89 F1 89 D0 80 F4 00 89 C3 89}
        $base64 = "\x55\x89\xE5\x56\x53\x81\xEC\x10\x03\x00\x00\xC7\x45\xF4\x00\x00\x00\x00\x8B\x45\x08\x8B\x90\x3C\x02\x00\x00\x8B\x80\x38\x02\x00\x00\x89\xC6\x83\xF6\x00\x89\xF1\x89\xD0\x80\xF4\x00\x89\xC3\x89" base64

    condition:
        any of them
}

rule hacktool_win_shellcode_donut_v093_4_x86
{
    meta:
        author = "threatintel@volexity.com"
        description = "Detection for donut loader shellcode version 0.9.3 x86 variant 4"
        date = "2023-05-08"
        reference = "https://github.com/TheWover/donut/blob/v0.9.3/loader_exe_x86.h"
        donut_loader_version = "0.9.3_V4"
        donut_bitness = "32"

    strings:
        $raw_bin = {55 8B EC 81 EC 10 03 00 00 83 65 BC 00 6A 5C 68 0C B0 42 00 E8 67 C5 00 00 59 59 85 C0 74 14 6A 5C 68 1C B0 42 00 E8 55 C5 00 00 59 59 40 89 45}
        $base64 = "\x55\x8B\xEC\x81\xEC\x10\x03\x00\x00\x83\x65\xBC\x00\x6A\x5C\x68\x0C\xB0\x42\x00\xE8\x67\xC5\x00\x00\x59\x59\x85\xC0\x74\x14\x6A\x5C\x68\x1C\xB0\x42\x00\xE8\x55\xC5\x00\x00\x59\x59\x40\x89\x45" base64

    condition:
        any of them
}

rule hacktool_win_shellcode_donut_v092_x64
{
    meta:
        author = "threatintel@volexity.com"
        description = "Detection for donut loader shellcode version 0.9.2 x64"
        date = "2023-05-08"
        reference = "https://github.com/TheWover/donut/blob/v0.9.2/payload/payload_exe_x64.h"
        donut_loader_version = "0.9.2"
        donut_bitness = "64"

    strings:
        $raw_bin = {55 48 89 e5 48 81 ec b0 00 00 00 48 89 4d 10 48 8b 45 10 48 89 45 e8 48 8b 45 e8 48 8b 40 48 48 89 45 e0 48 8b 45 e8 48 8b 48 28 48 8b 55 e0 48}
        $base64 = "\x55\x48\x89\xe5\x48\x81\xec\xb0\x00\x00\x00\x48\x89\x4d\x10\x48\x8b\x45\x10\x48\x89\x45\xe8\x48\x8b\x45\xe8\x48\x8b\x40\x48\x48\x89\x45\xe0\x48\x8b\x45\xe8\x48\x8b\x48\x28\x48\x8b\x55\xe0\x48" base64

    condition:
        any of them
}

rule hacktool_win_shellcode_donut_v092_x86
{
    meta:
        author = "threatintel@volexity.com"
        description = "Detection for donut loader shellcode version 0.9.2 x86"
        date = "2023-05-08"
        reference = "https://github.com/TheWover/donut/blob/v0.9.2/payload/payload_exe_x86.h"
        donut_loader_version = "0.9.2"
        donut_bitness = "32"

    strings:
        $raw_bin = {83 ec 20 53 55 56 57 8b 7c 24 34 ff 77 2c ff 77 28 ff 77 4c ff 77 48 57 e8 d1 1a 00 00 ff 77 2c 8b f0 ff 77 28 ff 77 54 ff 77 50 57 e8 bd 1a 00}
        $base64 = "\x83\xec\x20\x53\x55\x56\x57\x8b\x7c\x24\x34\xff\x77\x2c\xff\x77\x28\xff\x77\x4c\xff\x77\x48\x57\xe8\xd1\x1a\x00\x00\xff\x77\x2c\x8b\xf0\xff\x77\x28\xff\x77\x54\xff\x77\x50\x57\xe8\xbd\x1a\x00" base64

    condition:
        any of them
}

rule hacktool_win_shellcode_donut_v091_x64
{
    meta:
        author = "threatintel@volexity.com"
        description = "Detection for donut loader shellcode version 0.9.1 x64"
        date = "2023-05-08"
        reference = "https://github.com/TheWover/donut/blob/v0.9.1/payload/payload_exe_x64.h"
        donut_loader_version = "0.9.1"
        donut_bitness = "64"

    strings:
        $raw_bin = {48 89 5c 24 08 48 89 74 24 10 57 48 83 ec 60 33 d2 48 8b f9 48 8d 4c 24 20 44 8d 42 40 e8 a2 10 00 00 44 8b 0f 4c 8d 47 24 41 83 e9 24 48 8d 57}
        $base64 = "\x48\x89\x5c\x24\x08\x48\x89\x74\x24\x10\x57\x48\x83\xec\x60\x33\xd2\x48\x8b\xf9\x48\x8d\x4c\x24\x20\x44\x8d\x42\x40\xe8\xa2\x10\x00\x00\x44\x8b\x0f\x4c\x8d\x47\x24\x41\x83\xe9\x24\x48\x8d\x57" base64

    condition:
        any of them
}

rule hacktool_win_shellcode_donut_v091_x86
{
    meta:
        author = "threatintel@volexity.com"
        description = "Detection for donut loader shellcode version 0.9.1 x86"
        date = "2023-05-08"
        reference = "https://github.com/TheWover/donut/blob/v0.9.1/payload/payload_exe_x86.h"
        donut_loader_version = "0.9.1"
        donut_bitness = "32"

    strings:
        $raw_bin = {83 ec 20 8d 04 24 53 55 56 57 6a 20 6a 00 50 e8 69 0e 00 00 8b 74 24 40 8b 06 83 e8 24 50 8d 46 24 50 8d 46 14 50 8d 46 04 50 e8 2a 0c 00 00 ff}
        $base64 = "\x83\xec\x20\x8d\x04\x24\x53\x55\x56\x57\x6a\x20\x6a\x00\x50\xe8\x69\x0e\x00\x00\x8b\x74\x24\x40\x8b\x06\x83\xe8\x24\x50\x8d\x46\x24\x50\x8d\x46\x14\x50\x8d\x46\x04\x50\xe8\x2a\x0c\x00\x00\xff" base64

    condition:
        any of them
}

rule hacktool_win_shellcode_donut_v09_x64
{
    meta:
        author = "threatintel@volexity.com"
        description = "Detection for donut loader shellcode version 0.9 x64"
        date = "2023-05-08"
        reference = "https://github.com/TheWover/donut/blob/v0.9/payload/payload_exe_x64.h"
        donut_loader_version = "0.9"
        donut_bitness = "64"

    strings:
        $raw_bin = {55 48 89 e5 48 83 c4 80 48 89 4d 10 48 8b 45 10 48 89 45 f0 c7 45 ec 24 00 00 00 8b 55 ec 48 8b 45 f0 48 01 d0 48 89 45 e0 48 8b 45 f0 8b 00 2b}
        $base64 = "\x55\x48\x89\xe5\x48\x83\xc4\x80\x48\x89\x4d\x10\x48\x8b\x45\x10\x48\x89\x45\xf0\xc7\x45\xec\x24\x00\x00\x00\x8b\x55\xec\x48\x8b\x45\xf0\x48\x01\xd0\x48\x89\x45\xe0\x48\x8b\x45\xf0\x8b\x00\x2b" base64

    condition:
        any of them
}

rule hacktool_win_shellcode_donut_v09_x86
{
    meta:
        author = "threatintel@volexity.com"
        description = "Detection for donut loader shellcode version 0.9 x86"
        date = "2023-05-08"
        reference = "https://github.com/TheWover/donut/blob/v0.9/payload/payload_exe_x86.h"
        donut_loader_version = "0.9"
        donut_bitness = "32"

    strings:
        $raw_bin = {55 89 e5 56 53 83 ec 60 8b 45 08 89 45 f0 c7 45 ec 24 00 00 00 8b 55 f0 8b 45 ec 01 d0 89 45 e8 8b 45 f0 8b 00 2b 45 ec 8b 55 f0 8d 4a 14 8b 55}
        $base64 = "\x55\x89\xe5\x56\x53\x83\xec\x60\x8b\x45\x08\x89\x45\xf0\xc7\x45\xec\x24\x00\x00\x00\x8b\x55\xf0\x8b\x45\xec\x01\xd0\x89\x45\xe8\x8b\x45\xf0\x8b\x00\x2b\x45\xec\x8b\x55\xf0\x8d\x4a\x14\x8b\x55" base64
        
    condition:
        any of them
}
