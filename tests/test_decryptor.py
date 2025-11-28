import tempfile
from pathlib import Path

import py7zr
import pytest

from donut_decryptor.donut_decryptor import DonutDecryptor

archives = ["v092.7z", "v093.7z", "v1.7z"]


@pytest.mark.parametrize("filename", archives)
def test_decryptor(filename: str) -> None:
    archive = Path(__file__).resolve().parent.parent / "samples" / filename
    with tempfile.TemporaryDirectory() as dirname:
        directory = Path(dirname)
        with py7zr.SevenZipFile(archive, "r", password="infected") as a:
            a.extractall(path=dirname)
        # HACK: As v093.7z is nested...
        if filename == "v093.7z":
            directory = directory / "v093"
        for sample in directory.iterdir():
            decryptors = DonutDecryptor.find_donuts(sample)
            for decryptor in decryptors:
                assert decryptor.parse(directory)
