"""CLI interface for Donut-Decryptor."""

import logging
import sys
import traceback
from argparse import ArgumentParser
from pathlib import Path

from donut_decryptor._version import __version__
from donut_decryptor.donut_decryptor import DonutDecryptor

log_format = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
logging.basicConfig(format=log_format, level=logging.INFO, stream=sys.stdout)


def run() -> None:  # noqa: C901, D103
    logger = logging.getLogger(__name__)
    parser = ArgumentParser(prog="donut_decryptor", description="An extractor for the donut obfuscator")
    parser.add_argument("input_", type=Path, help="File or directory containing file(s) to parse")
    parser.add_argument(
        "--outdir",
        type=Path,
        help="Directory to write output to. Directory is created if not already existing",
        default=Path.cwd(),
    )
    parser.add_argument("--debug", action="store_true", help="Print debug information out")
    parser.add_argument("--pass-on-fail", action="store_true", help="Don't raise exceptions when parsing")
    parser.add_argument("--version", action="version", version=f"donut-decryptor {__version__}")

    args = parser.parse_args()

    if args.debug:
        loggers = [logging.getLogger(name) for name in logging.root.manager.loggerDict]
        for logger in loggers:
            logger.setLevel(logging.DEBUG)

    files_to_parse: list[Path] = []
    donuts: list[DonutDecryptor] = []
    input_: Path = args.input_

    # Build a list of files that may contain donuts.
    if input_.is_dir():
        logger.debug("Building file list")
        for item in input_.rglob("*"):
            if item.is_file() and not item.name.startswith("."):
                files_to_parse.extend([item])
    else:
        files_to_parse = [input_]

    # Make the output dir if required
    od: Path = args.outdir
    if not od.exists():
        od.mkdir(parents=True, exist_ok=True)

    # Collect the donuts
    logger.debug("Finding donuts in: %s files", len(files_to_parse))

    for f in files_to_parse:
        logger.debug("Parsing file: %s", f)
        donuts.extend(DonutDecryptor.find_donuts(f))

    logger.debug("Found %s donuts.", len(donuts))

    # Parse the donuts
    successes = 0
    attempted = 0
    for d in donuts:
        attempted += 1
        try:
            d.parse(od)
            successes += 1
        except Exception:
            logger.error("Encountered exception parsing file: %s", d.filepath)
            if logger.level == logging.DEBUG:
                traceback.print_exc()
            if args.pass_on_fail:
                continue
            raise
    logger.info("Parsed: %d of %d attempted files", successes, attempted)


if __name__ == "__main__":
    run()
