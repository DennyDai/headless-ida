import argparse
import code
from rpyc.utils.server import ThreadedServer
from . import HeadlessIda, HeadlessIdaRemote, HeadlessIdaServer


def headlessida_cli():
    parser = argparse.ArgumentParser(description='Headless IDA')
    parser.add_argument(
        'idat_path', help='Path to IDA Pro TUI executable / Host:Port of remote HeadlessIDA server')
    parser.add_argument('binary_path', help='Path to binary to analyze')
    parser.add_argument('script_path', nargs='?', help='Path to script to run')
    parser.add_argument('-c', '--command', help='Command to run after script')

    args = parser.parse_args()

    if ":" in args.idat_path:
        host, port = args.idat_path.split(":")
        headlessida = HeadlessIdaRemote(host, int(port), args.binary_path)
    else:
        headlessida = HeadlessIda(args.idat_path, args.binary_path)
    headlessida_dict = {"headlessida": headlessida, "HeadlessIda": HeadlessIda}

    if args.script_path:
        with open(args.script_path) as f:
            exec(compile(f.read(), args.script_path, 'exec'), headlessida_dict)
    elif args.command:
        exec(compile(args.command, '<string>', 'single'), headlessida_dict)

    else:
        code.interact(local=locals())


def headlessida_server_cli():
    parser = argparse.ArgumentParser(description='Headless IDA Server')
    parser.add_argument('idat_path', help='Path to IDA Pro TUI executable')
    parser.add_argument('host', help='Host to bind to')
    parser.add_argument('port', type=int, help='Port to listen on')

    args = parser.parse_args()

    ThreadedServer(HeadlessIdaServer(args.idat_path), hostname=args.host, port=args.port,
                   protocol_config={"allow_all_attrs": True}).start()
