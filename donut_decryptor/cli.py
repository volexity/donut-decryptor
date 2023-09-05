from argparse import ArgumentParser
import logging
import os
import sys
import traceback

from .donut_decryptor import DonutDecryptor


log_format = "%(asctime)s - %(name)s - %(levelname)s - %(message)s" 
logging.basicConfig(format=log_format,
                    level=logging.INFO,
                    stream=sys.stdout)

def valid_file_or_dir(s: str) -> str:
    if os.path.isfile(s):
        return s
    if os.path.isdir(s):
        return s
    raise ValueError(f"{s} is neither a file nor a directory.")


def valid_out_dir(s: str) -> str:
    if os.path.exists(s) and not os.path.isdir(s):
        raise ValueError(f"Error: Outdir {s} must be a directory if it " 
                         "already exists")
    if not os.path.exists(s):
        os.mkdir(s)
    return s


def run():
    logger = logging.getLogger(__name__)
    parser = ArgumentParser(prog='donut_decryptor',
                            description='An extractor for the donut obfuscator')
    parser.add_argument('input',
                        type=valid_file_or_dir,
                        help='File or directory containing file(s) to parse')
    parser.add_argument('--outdir',
                        type=valid_out_dir,
                        help="Directory to write output to. Directory is created if not"
                        " already existing",
                        default=os.getcwd())
    parser.add_argument("--debug",
                        action="store_true",
                        help="Print debug information out")
    parser.add_argument("--pass-on-fail",
                        action="store_true",
                        help="Don't raise exceptions when parsing")
    
    args = parser.parse_args()

    if args.debug:
        loggers = [logging.getLogger(name) for name in logging.root.manager.loggerDict]
        for logger in loggers:
            logger.setLevel(logging.DEBUG)

    files_to_parse = []
    donuts = []

    # Build a list of files that may contain donuts.
    if os.path.isdir(args.input):
        logger.debug("Building file list")
        for root, dirs, files in os.walk(args.input):
            for f in files:
                # ignore hidden files
                if f.startswith("."):
                    continue
                ptf = os.path.join(root, f)
                if os.path.isdir(ptf):
                    continue
                files_to_parse.append(ptf)
    else:
        files_to_parse = [args.input]

    # Collect the donuts
    logger.debug(f"Finding donuts in: {len(files_to_parse)} files")
    
    for f in files_to_parse:
        logger.debug(f"Parsing file: {f}")
        donuts.extend(DonutDecryptor.find_donuts(f))

    logger.debug(f"Found {len(donuts)} donuts.")
    # Parse the donuts
    successes = 0
    attempted = 0
    for d in donuts:
        attempted += 1
        try:
            d.parse(args.outdir)
            successes += 1  
        except Exception as e:
            logger.error(f"Encountered exception parsing file: {d.filepath}")
            if logger.level == logging.DEBUG:
                traceback.print_exc()
            if args.pass_on_fail:
                continue
            raise
    logger.info(f"Parsed: {successes} of {attempted} attempted files")


if __name__ == "__main__":
    run()
