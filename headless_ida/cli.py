import argparse
import code
from . import HeadlessIda


def main_cli():
    parser = argparse.ArgumentParser(description='Headless IDA')
    parser.add_argument('idat_path', help='Path to IDA Pro TUI executable')
    parser.add_argument('binary_path', help='Path to binary to analyze')
    parser.add_argument('script_path', nargs='?', help='Path to script to run')
    parser.add_argument('-c', '--command', help='Command to run after script')

    args = parser.parse_args()

    headlessida = HeadlessIda(args.idat_path, args.binary_path)
    headlessida_dict = {"headlessida": headlessida, "HeadlessIda": HeadlessIda}

    if args.script_path:
        with open(args.script_path) as f:
            exec(compile(f.read(), args.script_path, 'exec'), headlessida_dict)
    elif args.command:
        exec(compile(args.command, '<string>', 'single'), headlessida_dict)

    else:
        code.interact(local=locals())
