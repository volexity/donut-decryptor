# donut_decryptor

A configuration and module extractor for the [donut binary obfuscator](https://github.com/TheWover/donut)

## Description

`donut-decryptor` checks file(s) for known signatures of the donut obfuscator's loader shellcode. If located, it will parse the shellcode to locate, decrypt, and extract the `DONUT_INSTANCE` structure embedded in the binary, and report pertinent configuration data. If a `DONUT_MODULE` is present in the binary it is decrypted and dumped to disk.

### Requirements

`donut-decryptor` currently requires the separate installation of the [chaskey-lts](https://github.com/volexity/chaskey-lts) module.

## Installation

You can install `donut-decryptor` for usage by navigating to the root directory of the project and using pip:

```bash
cd /path/to/donut-decryptor
python -m pip install .
```

Following installation, a command-line script is available. For usage instructions use:

```bash
donut-decryptor --help
```

## Examples

The files present in the `samples` directory are 7z files password protected using the password `infected``, all of which contain donuts which can be decoded using this script.

## TODO list

* Update detection rules and instance parsing for alternative output formats:
  * Hex
  * C-String/Ruby
  * Python
  * C#
  * Powershell
* Consider moving loader/instance mapping to a YAML configuration file.
