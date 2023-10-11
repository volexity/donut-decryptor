"""File containing various definitions related to decryption of Donuts."""

from collections import namedtuple

ENTROPY_TYPES = (
    'DONUT_ENTROPY_NONE',    # No entropy
    'DONUT_ENTROPY_RANDOM',  # Random names
    'DONUT_ENTROPY_DEFAULT'  # Random names + Encryption
)

MOD_TYPES = (
    'DONUT_MODULE_INVALID',
    'DONUT_MODULE_NET_DLL',   # .NET DLL
    'DONUT_MODULE_NET_EXE',   # .NET EXE
    'DONUT_MODULE_DLL',       # Unmanaged DLL
    'DONUT_MODULE_EXE',       # Unmanaged EXE
    'DONUT_MODULE_VBS',       # VBScript
    'DONUT_MODULE_JS'         # JavaScript or JScript
)

COMP_TYPES = (
    'DONUT_COMPRESS_NONE',
    'DONUT_COMPRESS_APLIB',
    'DONUT_COMPRESS_LZNT1',
    'DONUT_COMPRESS_XPRESS'
)

INST_TYPES = (
    'DONUT_INSTANCE_EMBED',  # Module is embedded
    'DONUT_INSTANCE_HTTP',   # Module is downloaded from remote HTTP/HTTPS server
    'DONUT_INSTANCE_DNS'     # Module is downloaded from remote DNS server
)

offset = namedtuple('offset', ['pos', 'format'])
loader_mapping = namedtuple('loader_mapping', ['offsets', 'version'])
loader_offset = namedtuple('loader_offset', ['pos', 'value'])

# A note on development builds of donut:
#   Donut versions are distinguished by the alignment of the DONUT_INSTANCE
#   structure. Each tagged release of donut has a unique alignment of this
#   structure, and a unique signature for the Loader that processes it.
#   However, the window between releases have allowed for deployment of untagged
#   builds from the development branch. These untagged builds may contain
#   intermediate changes to the Instance structure, the Loader implementation,
#   or both.
#
#   Untagged builds are tracked using modifications to the DONUT_INSTANCE
#   structure use the following naming convention.
#       * <Previous tagged version #>_<Alpha Index>
#
#   Multiple variations of the loader may correlate to the same version of an
#   Instance. The dictionary below correlates all known unique alignments of
#   the DONUT_INSTANCE with their tracked names

instance_offset_map = {
    '0.9': {
        'size_instance': 0x588,
        'encryption_start': 0x24,
        'instance_key': offset(4, '16s'),
        'instance_nonce': offset(0x14, '16s'),
        'hash_iv': offset(0x128, 'Q'),
        'instance_signature': offset(0x3AC, '64s'),
        'instance_mac': offset(0x3F0, 'Q'),
        'instance_type': offset(0x318, 'i'),
        'download_uri': offset(0x31C, '128s'),
        'module_type': offset(0x420, 'I'),
        'module_key': offset(0x3F8, '16s'),
        'module_nonce': offset(0x408, '16s'),
        'module_length': offset(0x418, 'Q')
    },
    '0.9.1': {
        'size_instance': 0xC88,
        'encryption_start': 0x24,
        'instance_key': offset(4, '16s'),
        'instance_nonce': offset(0x14, '16s'),
        'hash_iv': offset(0x2A8, 'Q'),
        'instance_signature': offset(0x62C, '256s'),
        'instance_mac': offset(0x730, 'Q'),
        'instance_type': offset(0x518, 'i'),
        'download_uri': offset(0x51C, '256s'),
        'module_type': offset(0x760, 'I'),
        'module_key': offset(0x738, '16s'),
        'module_nonce': offset(0x748, '16s'),
        'module_length': offset(0x758, 'Q')
    },
    '0.9.2': {
        'size_instance': 0x2060,
        'encryption_start': 0x230,
        'instance_key': offset(4, '16s'),
        'instance_nonce': offset(0x14, '16s'),
        'hash_iv': offset(0x28, 'Q'),
        'instance_signature': offset(0x618, '256s'),
        'instance_mac': offset(0x718, 'Q'),
        'instance_type': offset(0x50C, 'i'),
        'download_uri': offset(0x510, '256s'),
        'module_type': offset(0x748, 'I'),
        'module_key': offset(0x720, '16s'),
        'module_nonce': offset(0x730, '16s'),
        'module_length': offset(0x2058, 'Q')
    },
    '0.9.3': {
        'size_instance': 0xE48,
        'encryption_start': 0x240,
        'entropy': offset(0x234, 'i'),
        'instance_key': offset(4, '16s'),
        'instance_nonce': offset(0x14, '16s'),
        'hash_iv': offset(0x28, 'Q'),
        'instance_signature': offset(0x7F0, '256s'),
        'instance_mac': offset(0x8F0, 'Q'),
        'instance_type': offset(0x6E4, 'i'),
        'download_uri': offset(0x6E8, '256s'),
        'module_key': offset(0x8F8, '256s'),
        'module_nonce': offset(0x908, '256s'),
        'module_length': offset(0x918, 'Q'),
        'module_type': offset(0x920, 'i'),
        'module_compression_type': offset(0x928, 'i'),
        'module_compressed_len': offset(0xE40, 'I')
    },
    '0.9.3_A': {
        'size_instance': 0xF48,
        'encryption_start': 0x240,
        'entropy': offset(0x234, 'i'),
        'instance_key': offset(4, '16s'),
        'instance_nonce': offset(0x14, '16s'),
        'hash_iv': offset(0x28, 'Q'),
        'instance_signature': offset(0x8F0, '256s'),
        'instance_mac': offset(0x9F0, 'Q'),
        'instance_type': offset(0x6E4, 'i'),
        'download_uri': offset(0x6E8, '256s'),
        'download_password': offset(0x7E8, '256s'),
        'module_key': offset(0x7F8, '16s'),
        'module_nonce': offset(0x808, '16s'),
        'module_length': offset(0xA18, 'Q'),
        'module_type': offset(0xA20, 'i'),
        'module_compression_type': offset(0xA28, 'i'),
        'module_compressed_len': offset(0xF40, 'I')
    },
    '0.9.3_B': {
        'size_instance': 0x1048,
        'encryption_start': 0x240,
        'entropy': offset(0x234, 'i'),
        'instance_key': offset(4, '16s'),
        'instance_nonce': offset(0x14, '16s'),
        'hash_iv': offset(0x28, 'Q'),
        'instance_signature': offset(0x9F0, '256s'),
        'instance_mac': offset(0xAF0, 'Q'),
        'instance_type': offset(0x6E4, 'i'),
        'download_uri': offset(0x6E8, '256s'),
        'download_username': offset(0x7E8, '256s'),
        'download_password': offset(0x8E8, '256s'),
        'module_key': offset(0xAF8, '16s'),
        'module_nonce': offset(0xB08, '16s'),
        'module_length': offset(0xB18, 'Q'),
        'module_type': offset(0xB20, 'i'),
        'module_compression_type': offset(0xB28, 'i'),
        'module_compressed_len': offset(0x1040, 'I')
    },
    '0.9.3_C': {
        'size_instance': 0x1060,
        'encryption_start': 0x240,
        'entropy': offset(0x234, 'i'),
        'instance_key': offset(4, '16s'),
        'instance_nonce': offset(0x14, '16s'),
        'hash_iv': offset(0x28, 'Q'),
        'instance_signature': offset(0xA08, '256s'),
        'instance_mac': offset(0xB08, 'Q'),
        'instance_type': offset(0x6FC, 'i'),
        'download_uri': offset(0x700, '256s'),
        'download_username': offset(0x800, '256s'),
        'download_password': offset(0x900, '256s'),
        'module_key': offset(0xB10, '16s'),
        'module_nonce': offset(0xB20, '16s'),
        'module_length': offset(0xB30, 'Q'),
        'module_type': offset(0xB38, 'i'),
        'module_compression_type': offset(0xB40, 'i'),
        'module_compressed_len': offset(0x1058, 'I')
    },
    '0.9.3_D': {
        'size_instance': 0x1078,
        'encryption_start': 0x240,
        'entropy': offset(0x234, 'i'),
        'instance_key': offset(4, '16s'),
        'instance_nonce': offset(0x14, '16s'),
        'hash_iv': offset(0x28, 'Q'),
        'instance_signature': offset(0xA1C, '256s'),
        'instance_mac': offset(0xB20, 'Q'),
        'instance_type': offset(0x710, 'i'),
        'download_uri': offset(0x714, '256s'),
        'download_username': offset(0x814, '256s'),
        'download_password': offset(0x914, '256s'),
        'module_key': offset(0xB28, '16s'),
        'module_nonce': offset(0xB38, '16s'),
        'module_length': offset(0xB48, 'Q'),
        'module_type': offset(0xB50, 'i'),
        'module_compression_type': offset(0xB58, 'i'),
        'module_compressed_len': offset(0x1070, 'I')
    },
    '0.9.3_E': {
        'size_instance': 0x1078,
        'encryption_start': 0x240,
        'entropy': offset(0x234, 'i'),
        'instance_key': offset(4, '16s'),
        'instance_nonce': offset(0x14, '16s'),
        'hash_iv': offset(0x28, 'Q'),
        'instance_signature': offset(0xA20, '256s'),
        'instance_mac': offset(0xB20, 'Q'),
        'instance_type': offset(0x714, 'i'),
        'download_uri': offset(0x718, '256s'),
        'download_username': offset(0x818, '256s'),
        'download_password': offset(0x918, '256s'),
        'module_key': offset(0xB28, '16s'),
        'module_nonce': offset(0xB38, '16s'),
        'module_length': offset(0xD48, 'Q'),
        'module_type': offset(0xB50, 'i'),
        'module_compression_type': offset(0xB58, 'i'),
        'module_compressed_len': offset(0x1070, 'I'),
    },
    '0.9.3_F': {
        'size_instance': 0x1288,
        'encryption_start': 0x240,
        'entropy': offset(0x234, 'i'),
        'instance_key': offset(4, '16s'),
        'instance_nonce': offset(0x14, '16s'),
        'hash_iv': offset(0x28, 'Q'),
        'instance_signature': offset(0xC30, '256s'),
        'instance_mac': offset(0xD30, 'Q'),
        'instance_type': offset(0x924, 'i'),
        'download_uri': offset(0x928, '256s'),
        'download_username': offset(0xA28, '256s'),
        'download_password': offset(0xB28, '256s'),
        'module_key': offset(0xD38, '16s'),
        'module_nonce': offset(0xD48, '16s'),
        'module_length': offset(0xD58, 'Q'),
        'module_type': offset(0xD60, 'i'),
        'module_compression_type': offset(0xD68, 'i'),
        'module_compressed_len': offset(0x1280, 'I'),
        'decoy_module': offset(0x629, '520s')
    },
    '1.0': {
        'size_instance': 0x1288,
        'encryption_start': 0x23C,
        'entropy': offset(0x234, 'i'),
        'instance_key': offset(4, '16s'),
        'instance_nonce': offset(0x14, '16s'),
        'hash_iv': offset(0x28, 'Q'),
        'instance_signature': offset(0xC2C, '256s'),
        'instance_mac': offset(0xD30, 'Q'),
        'instance_type': offset(0x920, 'i'),
        'download_uri': offset(0x924, '256s'),
        'download_username': offset(0xA24, '256s'),
        'download_password': offset(0xB24, '256s'),
        'module_key': offset(0xD38, '16s'),
        'module_nonce': offset(0xD48, '16s'),
        'module_length': offset(0xD58, 'Q'),
        'module_type': offset(0xD60, 'i'),
        'module_compression_type': offset(0xD68, 'i'),
        'module_compressed_len': offset(0x1280, 'I'),
        'decoy_module': offset(0x625, '520s')
    },
}

#   The below dictionary uses specific known offsets to disambiguate all known
#   variants of the donut loader from both tagged releases and development
#   builds. It can then be used to correlate the loader to a known instance
#   alignment using the dictionary `instance_offset_map`.

loader_version_map = {
    '0.9_64': [loader_mapping(None, '0.9')],
    '0.9_32': [loader_mapping(None, '0.9')],
    '0.9.1_64': [loader_mapping(None, '0.9.1')],
    '0.9.1_32': [loader_mapping(None, '0.9.1')],
    '0.9.2_64': [loader_mapping(None, '0.9.2')],
    '0.9.2_32': [loader_mapping(None, '0.9.2')],
    '0.9.3_V1_64': [
        loader_mapping(
            [   # 093_191221_loader_exe_x64
                loader_offset(0x35, 0xbb)
            ],
            '0.9.3'
        ),
        loader_mapping(
            [   # 093__1__loader_exe_x64
                loader_offset(0x35, 0x6f)
            ],
            '0.9.3'
        ),
        loader_mapping(
            [   # 093_200107_loader_exe_x64
                loader_offset(0x35, 0x8f)
            ],
            '0.9.3'
        ),
        loader_mapping(
            [   # 093_200317_loader_exe_x64
                loader_offset(0x35, 0x33)
            ],
            '0.9.3'
        ),
        loader_mapping(
            [   # 093_200319_loader_exe_x64
                loader_offset(0x35, 0x43),
                loader_offset(0x64a, 0x07),
                loader_offset(0x70b, 0x09),
            ],
            '0.9.3'
        ),
        loader_mapping(
            [   # 093_200327_loader_exe_x64
                loader_offset(0x35, 0x43),
                loader_offset(0x64a, 0x08),
                loader_offset(0x70b, 0x0a),
            ],
            '0.9.3_A'
        ),
        loader_mapping(
            [   # 093_200403_loader_exe_x64
                loader_offset(0x35, 0xff),
                loader_offset(0x36, 0x24)
            ],
            '0.9.3_B'
        ),
        loader_mapping(
            [   # 093_200411_loader_exe_x64
                loader_offset(0x35, 0x9f),
                loader_offset(0x36, 0x25),
                loader_offset(0x12E, 0x0c)
            ],
            '0.9.3_C'
        ),
        loader_mapping(
            [   # 093_200614_loader_exe_x64
                loader_offset(0x35, 0x9f),
                loader_offset(0x36, 0x25),
                loader_offset(0x12E, 0x20)
            ],
            '0.9.3_D'
        ),
        loader_mapping(
            [   # 093_210415_loader_exe_x64
                loader_offset(0x35, 0x97),
                loader_offset(0x36, 0x27)
            ],
            '0.9.3_D'
        ),
        loader_mapping(
            [   # 093_210521_loader_exe_x64
                loader_offset(0x35, 0xa7)
            ],
            '0.9.3_E'
        ),
        loader_mapping(
            [   # 093_221207_loader_exe_x64
                loader_offset(0x35, 0xaf),
                loader_offset(0x36, 0x2c)
            ],
            '0.9.3_F'
        )
    ],
    '0.9.3_V2_64': [
        loader_mapping(
            [   # 093_200218_loader_exe_x64
                loader_offset(0x35, 0xc9),
                loader_offset(0x6e, 0x2a)
            ],
            '0.9.3'
        ),
        loader_mapping(
            [   # 093_200330_loader_exe_x64
                loader_offset(0x35, 0xc9),
                loader_offset(0x6e, 0x02),
                loader_offset(0x6f, 0x0f)
            ],
            '0.9.3_A'
        ),
        loader_mapping(
            [   # 093_210129_loader_exe_x64
                loader_offset(0x35, 0xd4),
                loader_offset(0x6e, 0xf0),
                loader_offset(0x6f, 0x0e)
            ],
            '0.9.3'
        ),
        loader_mapping(
            [   # 093_211231_loader_exe_x64
                loader_offset(0x35, 0xd4),
                loader_offset(0x6e, 0x0b),
                loader_offset(0x6f, 0x0f)
            ],
            '0.9.3_F'
        ),
        loader_mapping(
            [   # 093_220104_loader_exe_x64
                loader_offset(0x35, 0xd4),
                loader_offset(0x6e, 0xc3),
                loader_offset(0x6f, 0x14)
            ],
            '0.9.3_F'
        )
    ],
    '0.9.3_V1_32': [
        loader_mapping(
            [   # 093_191221_loader_exe_x86
                loader_offset(0x3b, 0xb8),
                loader_offset(0x3c, 0x20)
            ],
            '0.9.3'
        ),
        loader_mapping(
            [   # 093__1__loader_exe_x86
                loader_offset(0x3b, 0x70),
                loader_offset(0x3c, 0x20)
            ],
            '0.9.3'
        ),
        loader_mapping(
            [   # 093_200317_loader_exe_x86
                loader_offset(0x3b, 0x54),
                loader_offset(0x3c, 0x20)
            ],
            '0.9.3'
        ),
        loader_mapping(
            [   # 093_200319_loader_exe_x86
                loader_offset(0x3b, 0x72),
                loader_offset(0x3c, 0x20),
                loader_offset(0x6f6, 0x07)
            ],
            '0.9.3'
        ),
        loader_mapping(
            [   # 093_200327_loader_exe_x86
                loader_offset(0x3b, 0x72),
                loader_offset(0x3c, 0x20),
                loader_offset(0x6f6, 0x08)
            ],
            '0.9.3_A'
        ),
        loader_mapping(
            [   # 093_200403_loader_exe_x86
                loader_offset(0x3b, 0xe3),
                loader_offset(0x3c, 0x21)
            ],
            '0.9.3_B'
        ),
        loader_mapping(
            [   # 093_200624_loader_exe_x86
                loader_offset(0x3b, 0x57),
                loader_offset(0x3c, 0x22)
            ],
            '0.9.3_D'
        ),
        loader_mapping(
            [   # 093_210415_loader_exe_x86
                loader_offset(0x3b, 0x0c),
                loader_offset(0x3c, 0x23)
            ],
            '0.9.3_D'
        ),
        loader_mapping(
            [   # 093_210521_loader_exe_x86
                loader_offset(0x3b, 0x1d),
                loader_offset(0x3c, 0x23)
            ],
            '0.9.3_E'
        ),
        loader_mapping(
            [   # 093_221207_loader_exe_x86
                loader_offset(0x3b, 0x22),
                loader_offset(0x3c, 0x27)
            ],
            '0.9.3_F'
        )
    ],
    '0.9.3_V2_32': [
        loader_mapping(
            [   # 093_200218_loader_exe_x86
                loader_offset(0x84, 0xd6)
            ],
            '0.9.3'
        ),
        loader_mapping(
            [   # 093_200330_loader_exe_x86
                loader_offset(0x84, 0xa6)
            ],
            '0.9.3_A'
        )
    ],
    '0.9.3_V3_32': [
        loader_mapping(
            [   # 093_210129_loader_exe_x86
                loader_offset(0x76, 0x82),
                loader_offset(0x77, 0x0c)
            ],
            '0.9.3'
        ),
        loader_mapping(
            [   # 093_211231_loader_exe_x86
                loader_offset(0x76, 0xbc),
                loader_offset(0x77, 0x0c)
            ],
            '0.9.3_F'
        ),
        loader_mapping(
            [   # 093_220104_loader_exe_x86
                loader_offset(0x76, 0x43),
                loader_offset(0x77, 0x11)
            ],
            '0.9.3_F'
        )
    ],
    '0.9.3_V4_32': [loader_mapping(None, '0.9.3_C')],
    '1.0_64': [loader_mapping(None, '1.0')],
    '1.0_32': [loader_mapping(None, '1.0')]
}
