"""All logic for decrypting donuts."""

# Builtins
from __future__ import annotations

import json
import logging
import struct
from pathlib import Path

# Installables
import aplib
import lznt1
import yara
from chaskey import Chaskey

# locals
from donut_decryptor.definitions import (
    COMP_TYPES,
    ENTROPY_TYPES,
    INST_TYPES,
    MOD_TYPES,
    LoaderMapping,
    Offset,
    instance_offset_map,
    loader_version_map,
)

logger = logging.getLogger(__name__)

RULES_PATH = Path(__file__).parent / "data" / "rules.yar"


class DonutDecryptor:
    """Extractor/Decryptor for the donut binary obfuscator."""

    rules = yara.compile(filepath=str(RULES_PATH))

    def _map_loader_to_instance(self, loader_mappings: list[LoaderMapping]) -> str | None:
        if not loader_mappings:
            return None

        if len(loader_mappings) == 1:
            return loader_mappings[0].version

        with self.filepath.open("rb") as f:
            # Have to read at least 0x70b (1803) bytes base on the largest
            # disambiguation offset listed in definitions.py
            f.seek(self.offset_loader_start)
            loader_chunk = f.read(1804)

        for mapping in loader_mappings:
            c = 0
            while c < len(mapping.offsets):  # type: ignore[arg-type]
                if loader_chunk[mapping.offsets[c].pos] != mapping.offsets[c].value:  # type: ignore[arg-type,index]
                    break
                c += 1
            if c == len(mapping.offsets):  # type: ignore[arg-type]
                return mapping.version
        return None

    def __init__(self, filepath: Path, loader_version: str, bitness: str, offset_loader: int) -> None:
        """Initialize a donut_decryptor.

        NOTE: donut_decryptor is not designed to be initialized directly. It's
        recommended to call donut_decryptor.find_donuts() instead.

        Args:
            self: Object instance
            filepath (str): Qualified path of the file containing the instance
            loader_version (str): The donut loader version string.
            version (str): A supported donut version string. Any of:
                        '1.0', '0.9.3', '0.9.2', '0.9.1', or '0.9'
            bitness (str): Indicates the bit width of the shellcode. Must be one of:
                        '32' or '64'
            offset_loader (int): Offset in file to start of the donut loader

        Returns:
            None

        """
        if bitness not in ["64", "32"]:
            msg = f"Error: Unsupported bitness value provided: {bitness}"
            raise ValueError(msg)

        if not filepath.is_file():
            msg = f"Error: Invalid filepath provided: {filepath}"
            raise ValueError(msg)

        self.filepath = filepath
        self.offset_loader_start = offset_loader
        self.loader_version = loader_version + "_" + bitness

        loader_mappings = loader_version_map.get(self.loader_version, None)

        if not loader_mappings:
            msg = f"Error: unsupported loader version: {self.loader_version}"
            raise ValueError(msg)

        self.instance_version = self._map_loader_to_instance(loader_mappings)

        logger.info("Parsing donut from file: %s ", filepath)
        logger.info("Using %s, and instance version: %s", self.loader_version, self.instance_version)

        if self.instance_version not in instance_offset_map:
            msg = f"Error: unsupported instance version: {self.instance_version}"
            raise ValueError(msg)

        self.offsets = instance_offset_map[self.instance_version]

    @classmethod
    def find_donuts(cls, filepath: Path) -> list[DonutDecryptor]:  # noqa: C901
        """Find donuts in `filepath`.

        Class method to find donuts in `filepath` for donut shellcode and return a
        list of DonutDecryptor objects for each located Instance

        Args:
            cls : donut_decryptor class object
            filepath (str): Qualified path of the file to scan

        Returns:
            list[donut_decryptor]: Contains one entry per unique instance

        """
        if not filepath.is_file():
            msg = f"Error: Invalid filepath provided: {filepath}"
            raise ValueError(msg)

        matches = cls.rules.match(str(filepath))
        results: list[DonutDecryptor] = []
        if len(matches) == 0:
            return results

        found_x64_loader = False
        for m in matches:
            loader_version = m.meta["donut_loader_version"]
            bitness = m.meta["donut_bitness"]
            # If both x64 and x86 loaders are found in the same file it's
            # likely a case of DONUT_ARCH_X84 config type, which uses the same
            # instance for both loaders, so skip the secondary x86 loader
            if len(matches) == 2 and bitness == "64":  # noqa: PLR2004
                found_x64_loader = True
            if bitness == "32" and found_x64_loader:
                continue

            # Handle matches
            if len(m.strings) > 1:
                logger.error(f"Warning: Found multiple of same loader string in file: {m.strings}")  # noqa: G004

            for s in m.strings:
                if s.identifier != "$raw_bin":
                    # TODO: Identify alternative instance type, Decode to
                    # binary and process
                    logger.error("Warning: found unsupported instance format...skipping")
                    continue
                if len(s.instances) > 1:
                    logger.error("Warning: found two instance of same loader pattern")
                for i in s.instances:
                    results.extend([DonutDecryptor(filepath, loader_version, bitness, i.offset)])
        return results

    def _locate_instance(self) -> bool:
        with self.filepath.open("rb") as f:
            # Read file at least up to the instance offset
            b = f.read(self.offset_loader_start)

        logger.info("Locating instance in file: %s", self.filepath)

        # Search backwards for the 'pop rcx'
        instance_head = 0
        for x in range(len(b) - 1, 0, -1):
            if b[x] == 0x59:  # noqa: PLR2004
                instance_head = x
                logger.debug("Found instance preamble starting at: %s", hex(x))
                break
        # Search backwards for a 'call' instruction with offset to 'pop rcx'
        for x in range(instance_head, -1, -1):
            if b[x] == 0xE8:  # noqa: PLR2004
                call_offset = struct.unpack_from("<I", b, x + 1)[0]
                interval = instance_head - x
                logger.debug(
                    "Found possible call to preamble offset at: %s,Call offset: %s, interval size: %s",
                    hex(x),
                    hex(call_offset + 5),
                    hex(interval),
                )
                if interval >= call_offset + 5 and interval - call_offset + 5 <= 16:  # noqa: PLR2004
                    logger.info("Found instance at: %s", hex(x + 5))
                    self.raw_instance = b[x + 5 : instance_head]
                    break

        if hasattr(self, "raw_instance"):
            return True
        logger.error("Failed to find instance in %s", self.filepath)
        return False

    def _decrypt_instance(self) -> bool:
        if not hasattr(self, "raw_instance"):
            msg = "Error: Need an instance to decrypt"
            raise AttributeError(msg)

        self.entropy = None
        if "entropy" in self.offsets:
            off: Offset = self.offsets["entropy"]  # type: ignore[assignment]
            entropy = struct.unpack_from(off.format, self.raw_instance, off.pos)[0]
            if entropy and entropy <= len(ENTROPY_TYPES):
                self.entropy = ENTROPY_TYPES[entropy - 1]
            elif entropy == 0:
                # Handling for anomalous value that can occur in 0.9.3_2 instances
                self.entropy = ENTROPY_TYPES[0]
            else:
                msg = f"Error: Invalid entropy type: {entropy}"
                raise ValueError(msg)
            logger.debug("Entropy type: %s. Entropy enum: %s", self.entropy, entropy)
        if self.entropy is None or self.entropy == "DONUT_ENTROPY_DEFAULT":
            # Extract Key and Nonce from instance
            key_offset: Offset = self.offsets["instance_key"]  # type: ignore[assignment]
            nonce_offset: Offset = self.offsets["instance_nonce"]  # type: ignore[assignment]
            key = struct.unpack_from(key_offset.format, self.raw_instance, key_offset.pos)[0]
            nonce = struct.unpack_from(nonce_offset.format, self.raw_instance, nonce_offset.pos)[0]

            # Extract and decrypt cipher text from instance
            cipher = Chaskey("ctr", key, nonce)
            logger.debug(
                "Decrypting instance of length: %d with key: %s and nonce: %s",
                len(self.raw_instance),
                key,
                nonce,
            )
            enc_start: int = self.offsets["encryption_start"]  # type:ignore[assignment]
            dec = cipher.decrypt(self.raw_instance[enc_start:])
            if not dec:
                return False
            self.instance = self.raw_instance[:enc_start] + dec
            return True
        logger.info("No encryption, setting instance to raw instance")
        self.instance = self.raw_instance
        return True

    def _decompress_module(self) -> bytes:
        size: int = self.offsets["size_instance"]  # type: ignore[assignment]
        mod_data = self.instance[size:]
        if self.compression_type_name is not None:
            off: Offset = self.offsets["module_compressed_len"]  # type: ignore[assignment]
            compressed_len = struct.unpack_from(off.format, self.instance, off.pos)[0]
            logger.debug("Decompressing compression_type: %s", self.compression_type_name)
            if self.compression_type_name != "DONUT_COMPRESS_NONE":
                mod_data = mod_data[:compressed_len]
                if self.compression_type_name == "DONUT_COMPRESS_APLIB":
                    mod_data = aplib.decompress(mod_data)
                elif self.compression_type_name == "DONUT_COMPRESS_LZNT1":
                    mod_data = lznt1.decompress(mod_data)
                elif self.compression_type_name == "DONUT_COMPRESS_XPRESS":
                    msg = "Error: Xpress decompression is not supported"
                    raise ValueError(msg)
                else:
                    msg = f"Error: Unexpected compression_type encountered:{self.compression_type_name}"
                    raise ValueError(msg)
        return mod_data

    def _write_module(self, outdir: Path, mod_data: bytes) -> None:
        out_mod = outdir / f"mod_{Path(self.filepath).name}"
        logger.info("Writing module to: %s", out_mod)
        with out_mod.open("wb") as f:
            f.write(mod_data)

    def _write_instance(self, outdir: Path) -> None:  # noqa: C901, PLR0912, PLR0915
        inst_data = {}
        inst_data["File"] = self.filepath
        off: Offset = self.offsets["instance_type"]  # type: ignore[assignment]
        instance_type = struct.unpack_from(off.format, self.instance, off.pos)[0]

        if instance_type <= len(INST_TYPES):
            instance_type_name = INST_TYPES[instance_type - 1]
            inst_data["Instance Type"] = instance_type_name
        else:
            msg = "Error: Instance type parsing failed"
            raise ValueError(msg)
        logger.debug("Got instance of type: %s , %s", instance_type, instance_type_name)

        if self.entropy:
            inst_data["Entropy Type"] = self.entropy

        if "decoy_module" in self.offsets:
            decoy_off: Offset = self.offsets["decoy_module"]  # type: ignore[assignment]
            decoy = struct.unpack_from(decoy_off.format, self.instance, decoy_off.pos)[0]
            inst_data["Decoy Module"] = decoy.decode().strip("\0")

        if instance_type_name == "DONUT_INSTANCE_EMBED":
            # Get module information if type is DONUT_INSTANCE_EMBED
            mod_type_off: Offset = self.offsets["module_type"]  # type: ignore[assignment]
            module_type = struct.unpack_from(mod_type_off.format, self.instance, mod_type_off.pos)[0]
            if module_type <= len(MOD_TYPES):
                inst_data["Module Type"] = MOD_TYPES[module_type - 1]
            else:
                msg = "Error: module type parsing failed"
                raise ValueError(msg)
            # Compression added in 0.9.3, only output if offset is present
            if "module_compression_type" not in self.offsets:
                self.compression_type_name = None
            else:
                comp_type_off: Offset = self.offsets["module_compression_type"]  # type: ignore[assignment]
                comp_type = struct.unpack_from(comp_type_off.format, self.instance, comp_type_off.pos)[0]
                if comp_type <= len(COMP_TYPES):
                    self.compression_type_name = COMP_TYPES[comp_type - 1]
                    logger.debug("Setting compression type to: %s", self.compression_type_name)
                    inst_data["Compression Type"] = self.compression_type_name
                else:
                    msg = "Error: module compression type parsing failed"
                    raise ValueError(msg)
            self._write_module(outdir=outdir, mod_data=self._decompress_module())

        elif instance_type_name in ["DONUT_INSTANCE_HTTP", "DONUT_INSTANCE_DNS"]:
            uri_off: Offset = self.offsets["download_uri"]  # type: ignore[assignment]
            uri = struct.unpack_from(uri_off.format, self.instance, uri_off.pos)[0]
            inst_data["Download URL"] = uri.decode().strip("\0")
            # Username and Password added in 1.0, only output if offset is
            # present
            if "download_username" in self.offsets:
                user_off: Offset = self.offsets["download_username"]  # type: ignore[assignment]
                username = struct.unpack_from(user_off.format, self.instance, user_off.pos)[0]
                inst_data["Download Username"] = username.decode().strip("\0")
            if "download_password" in self.offsets:
                pswd_off: Offset = self.offsets["download_password"]  # type: ignore[assignment]
                password = struct.unpack_from(pswd_off.format, self.instance, pswd_off.pos)[0]
                inst_data["Download Password"] = password.decode().strip("\0")

            key_off: Offset = self.offsets["module_key"]  # type: ignore[assignment]
            mod_key = struct.unpack_from(key_off.format, self.instance, key_off.pos)[0]
            inst_data["Module Key"] = mod_key

            nonce_off: Offset = self.offsets["module_nonce"]  # type: ignore[assignment]
            mod_nonce = struct.unpack_from(nonce_off.format, self.instance, nonce_off.pos)[0]
            inst_data["Module Nonce"] = mod_nonce
        else:
            logger.error("Invalid instance type. Something went very wrong")

        out_inst = Path(outdir) / f"inst_{Path(self.filepath).name}"
        logger.info("Writing instance meta data to: %s", out_inst)
        with out_inst.open("w") as f:
            f.write(json.dumps(inst_data, indent=4, default=str))

    def parse(self, outdir: Path) -> bool:
        """Extract and decrypt instance data and embedded module from a donut.

        Args:
            self: Object instance
            outdir (Path): Directory to write output files to

        Returns:
            bool: Indicates successful extraction

        """
        logger.debug("Trying to parse %s of version %s", self.filepath, self.instance_version)
        if not outdir.is_dir():
            msg = "Error: Invalid outdir provided"
            raise ValueError(msg)

        if self._locate_instance() and self._decrypt_instance():
            self._write_instance(outdir)
            return True
        return False
