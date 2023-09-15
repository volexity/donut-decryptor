"""All logic for decrypting donuts."""

# Builtins
from __future__ import annotations

import logging
import os
import struct
import json
from typing import List, Union

# Installables
import aplib
from chaskey import Chaskey  # available from the Volexity Github
import lznt1
import yara

# locals
from .definitions import (
    MOD_TYPES,
    INST_TYPES,
    COMP_TYPES,
    ENTROPY_TYPES,
    loader_version_map,
    loader_mapping,
    instance_offset_map,
)


logger = logging.getLogger(__name__)

RULES_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                          "data",
                          "rules.yar")


class DonutDecryptor():
    """Extractor/Decryptor for the donut binary obfuscator."""

    rules = yara.compile(filepath=RULES_PATH)

    def _map_loader_to_instance(self, loader_mappings: List[loader_mapping]) -> Union[str, None]:
        if not loader_mappings:
            return None

        if len(loader_mappings) == 1:
            return loader_mappings[0].version

        with open(self.filepath, 'rb') as f:
            # Have to read at least 0x70b (1803) bytes base on the largest
            # disambiguation offset listed in definitions.py
            f.seek(self.offset_loader_start)
            loader_chunk = f.read(1804)

        for mapping in loader_mappings:
            c = 0
            while c < len(mapping.offsets):
                if loader_chunk[mapping.offsets[c].pos] != mapping.offsets[c].value:
                    break
                c += 1
            if c == len(mapping.offsets):
                return mapping.version

    def __init__(self,
                 filepath: str,
                 loader_version: str,
                 bitness: str,
                 offset_loader: int) -> None:
        """Initialize a donut_decryptor.

        NOTE: donut_decryptor is not designed to be initialized directly. It's
        recommended to call donut_decryptor.find_donuts() instead.

        Args:
            self: Object instance
            filepath (str): Qualified path of the file containing the instance
            version (str): A supported donut version string. Any of:
                        '1.0', '0.9.3', '0.9.2', '0.9.1', or '0.9'
            bitness (str): Indicates the bit width of the shellcode. Must be one of:
                        '32' or '64'
            offset_loader (int): Offset in file to start of the donut loader

        Returns:
            None
        """
        if bitness not in ['64', '32']:
            raise ValueError(f'Error: Unsupported bitness value provided: {bitness}')

        if not os.path.isfile(filepath):
            raise ValueError(f'Error: Invalid filepath provided: {filepath}')

        self.filepath = filepath
        self.offset_loader_start = offset_loader
        self.loader_version = loader_version + '_' + bitness

        loader_mappings = loader_version_map.get(self.loader_version, None)

        if not loader_mappings:
            raise ValueError(f'Error: unsupported loader version: {self.loader_version}')

        self.instance_version = self._map_loader_to_instance(loader_mappings)

        logger.info(f"Parsing donut from file: {filepath} with loader version: "
                    f"{self.loader_version}, and instance version: {self.instance_version}")

        if self.instance_version not in instance_offset_map:
            raise ValueError(f'Error: unsupported instance version: {self.instance_version}')

        self.offsets = instance_offset_map[self.instance_version]

    @classmethod
    def find_donuts(cls, filepath: str) -> List[DonutDecryptor]:
        """Find donuts in `filepath`.

        Class method to find donuts in `filepath` for donut shellcode and return a
        list of DonutDecryptor objects for each located Instance

        Args:
            cls : donut_decryptor class object
            filepath (str): Qualified path of the file to scan

        Returns:
            list[donut_dcryptor]: Contains one entry per unique instance
        """
        if not os.path.isfile(filepath):
            raise ValueError(f'Error: Invalid filepath provided: {filepath}')

        matches = cls.rules.match(filepath)
        results = []
        if len(matches) == 0:
            return results

        found_x64_loader = False
        for m in matches:
            loader_version = m.meta["donut_loader_version"]
            bitness = m.meta["donut_bitness"]
            # If both x64 and x86 loaders are found in the same file it's
            # likely a case of DONUT_ARCH_X84 config type, which uses the same
            # instance for both loaders, so skip the secondary x86 loader
            if len(matches) == 2 and bitness == '64':
                found_x64_loader = True
            if bitness == '32' and found_x64_loader:
                continue

            # Handle matches
            if len(m.strings) > 1:
                logger.error(f"Warning: Found multiple of same loader string in file: {m.strings}")

            for s in m.strings:
                if s.identifier != '$raw_bin':
                    # TODO: Identify alternative instance type, Decode to
                    # binary and process
                    logger.error("Warning: found unsupported instance format...skipping")
                    continue
                if len(s.instances) > 1:
                    logger.error("Warning: found two instance of same loader pattern")
                for i in s.instances:
                    results.append(DonutDecryptor(filepath, loader_version, bitness, i.offset))
        return results

    def _locate_instance(self) -> bool:
        with open(self.filepath, 'rb') as f:
            # Read file at least up to the instance offset
            b = f.read(self.offset_loader_start)

        # Search backwards for the 'pop rcx'
        instance_end = 0
        for x in range(len(b)-1, 0, -1):
            if b[x] == 0x59:
                instance_end = x
                break
        # Search backwards for a 'call' instruction with offset to 'pop rcx'
        for x in range(instance_end-self.offsets['size_instance'], -1, -1):
            if b[x] == 0xe8:
                call_offset = struct.unpack_from('<I', b, x+1)[0]
                ie = instance_end - x + 1
                if ie >= call_offset + 5 & ie - call_offset + 5 <= 16:
                    self.raw_instance = b[x+5:instance_end]
                    break

        if hasattr(self, 'raw_instance'):
            return True
        else:
            logger.error(f"Failed to find instance in {self.filepath}")
            return False
        raise Exception("Unreachable code reached.")

    def _decrypt_instance(self) -> bool:
        if not hasattr(self, 'raw_instance'):
            raise AttributeError("Error: Need an instance to decrypt")

        self.entropy = None
        if 'entropy' in self.offsets:
            off = self.offsets['entropy']
            entropy = (
                struct.unpack_from(off.format, self.raw_instance, off.pos)[0]
            )
            if entropy <= len(ENTROPY_TYPES):
                self.entropy = ENTROPY_TYPES[entropy-1]
            else:
                raise ValueError("Error: Invalid entropy type")

        if not self.entropy or self.entropy == 'DONUT_ENTROPY_DEFAULT':
            # Extract Key and Nonce from instance
            key_offset = self.offsets['instance_key']
            nonce_offset = self.offsets['instance_nonce']
            key = struct.unpack_from(key_offset.format,
                                     self.raw_instance,
                                     key_offset.pos)[0]
            nonce = struct.unpack_from(nonce_offset.format,
                                       self.raw_instance,
                                       nonce_offset.pos)[0]

            # Extract and decrypt cipher text from instance
            cipher = Chaskey('ctr', key, nonce)

            dec = cipher.decrypt(self.raw_instance[self.offsets['encryption_start']:])
            if not dec:
                return False

            self.instance = self.raw_instance[:self.offsets['encryption_start']] + dec
            return True
        else:
            self.instance = self.raw_instance

    def _decompress_module(self) -> bytes:
        mod_data = self.instance[self.offsets['size_instance']:]
        if self.compression_type_name is not None:
            off = self.offsets['module_compressed_len']
            compressed_len = struct.unpack_from(off.format, self.instance, off.pos)[0]
            logger.debug(f"Decompressing compression_type: {self.compression_type_name}")
            if self.compression_type_name != "DONUT_COMPRESS_NONE":
                mod_data = mod_data[:compressed_len]
                if self.compression_type_name == 'DONUT_COMPRESS_APLIB':
                    mod_data = aplib.decompress(mod_data)
                elif self.compression_type_name == 'DONUT_COMPRESS_LZNT1':
                    mod_data = lznt1.decompress(mod_data)
                elif self.compression_type_name == 'DONUT_COMPRESS_XPRESS':
                    logger.error(f"Unsupported compression_type: {self.compression_type_name}")
                    raise ValueError("Error: Xpress decompression is not supported")
                else:
                    raise ValueError("Error: Unexpected compression_type encountered:"
                                     f"{self.compression_type_name}")
        return mod_data

    def _write_module(self, outdir: str, mod_data: bytes) -> None:
        out_mod = os.path.join(outdir,
                               f'mod_{os.path.basename(self.filepath)}')
        logger.info(f"Writing module to: {out_mod}")
        with open(out_mod, 'wb') as f:
            f.write(mod_data)

    def _write_instance(self, outdir: str) -> None:
        inst_data = {}
        inst_data['File'] = self.filepath
        off = self.offsets['instance_type']
        instance_type = struct.unpack_from(off.format, self.instance, off.pos)[0]

        if instance_type <= len(INST_TYPES):
            instance_type_name = INST_TYPES[instance_type-1]
            inst_data['Instance Type'] = instance_type_name
        else:
            raise ValueError("Error: Instance type parsing failed")
        logger.debug(f"Got instance of type: {instance_type} , {instance_type_name}")

        if self.entropy:
            inst_data['Entropy Type'] = self.entropy

        if 'decoy_module' in self.offsets:
            off = self.offsets['decoy_module']
            decoy = struct.unpack_from(off.format, self.instance, off.pos)[0]
            inst_data['Decoy Module'] = decoy.decode().strip('\0')

        if instance_type_name == 'DONUT_INSTANCE_EMBED':
            # Get module information if type is DONUT_INSTANCE_EMBED
            off = self.offsets['module_type']
            module_type = (
                struct.unpack_from(off.format, self.instance, off.pos)[0]
            )
            if module_type <= len(MOD_TYPES):
                inst_data['Module Type'] = MOD_TYPES[module_type-1]
            else:
                raise ValueError("Error: module type parsing failed")
            # Compression added in 0.9.3, only output if offset is present
            if 'module_compression_type' not in self.offsets:
                self.compression_type_name = None
            else:
                off = self.offsets['module_compression_type']
                comp_type = (
                    struct.unpack_from(off.format, self.instance, off.pos)[0]
                )
                if comp_type <= len(COMP_TYPES):
                    self.compression_type_name = COMP_TYPES[comp_type-1]
                    logger.debug(f"Setting compression type to: {self.compression_type_name}")
                    inst_data['Compression Type'] = self.compression_type_name
                else:
                    raise ValueError("Error: module compression type parsing failed")
            self._write_module(outdir=outdir,
                               mod_data=self._decompress_module())

        elif instance_type_name in ['DONUT_INSTANCE_HTTP', 'DONUT_INSTANCE_DNS']:
            off = self.offsets['download_uri']
            uri = struct.unpack_from(off.format, self.instance, off.pos)[0]
            inst_data['Download URL'] = uri.decode().strip('\0')
            # Username and Password added in 1.0, only output if offset is
            # present
            if 'download_username' in self.offsets:
                off = self.offsets['download_username']
                username = struct.unpack_from(off.format,
                                              self.instance,
                                              off.pos)[0]
                inst_data['Download Username'] = username.decode().strip('\0')
            if 'download_password' in self.offsets:
                off = self.offsets['download_password']
                password = struct.unpack_from(off.format,
                                              self.instance,
                                              off.pos)[0]
                inst_data['Download Password'] = password.decode().strip('\0')

            off = self.offsets['module_key']
            mod_key = struct.unpack_from(off.format,
                                         self.instance,
                                         off.pos)[0]
            inst_data['Module Key'] = mod_key

            off = self.offsets['module_nonce']
            mod_nonce = (
                struct.unpack_from(off.format, self.instance, off.pos)[0]
            )
            inst_data['Module Nonce'] = mod_nonce
        else:
            logger.error("Invalid instance type. Something went very wrong")
            ############################################################
            # Uncomment to dump full binary instance on parsing error
            # outfile = (
            #     os.path.join(outdir, 'test_' + os.path.basename(self.filepath))
            # )
            # with open(outfile, 'wb') as f:
            #     f.write(self.instance)
            ############################################################

        # Write instance info to file
        out_inst = os.path.join(outdir, 'inst_' + os.path.basename(self.filepath))
        logger.info(f"Writing instance meta data to: {out_inst}")
        with open(out_inst, 'w') as f:
            f.write(json.dumps(inst_data, indent=4))

    def parse(self, outdir: str) -> bool:
        """Extract and decrypt instance data and embedded module from a donut.

        Args:
            self: Object instance
            outdir (str): Directory to write output files to

        Returns:
            bool: Indicates successful extraction
        """
        logger.debug(f"Trying to parse {self.filepath} of version {self.instance_version}")
        if not os.path.isdir(outdir):
            raise ValueError('Error: Invalid outdir provided')

        if (self._locate_instance() and self._decrypt_instance()):
            self._write_instance(outdir)
            return True
        else:
            return False
