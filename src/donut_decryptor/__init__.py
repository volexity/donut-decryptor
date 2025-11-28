"""Retrieve inner payloads from Donut samples."""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("donut-decryptor")
except PackageNotFoundError:
    __version__ = "0.0.0-unknown"
