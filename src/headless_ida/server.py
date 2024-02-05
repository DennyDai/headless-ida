import rpyc
import socket
import os
import subprocess
import tempfile
import site
import sys

from .helpers import escape_path, ForwardIO


def HeadlessIdaServer(idat_path):
    class _HeadlessIdaServer(rpyc.Service):
        def exposed_init(self, binary):
            binary_file = tempfile.NamedTemporaryFile(delete=False)
            binary_file.write(binary)
            binary_file.flush()
            binary_file.close()
            binary_path = binary_file.name

            server_path = os.path.join(os.path.realpath(
                os.path.dirname(__file__)), "ida_script.py")
            port = 8000
            with socket.socket() as s:
                s.bind(('', 0))
                port = s.getsockname()[1]
            os.environ["PYTHONPATH"] = os.pathsep.join(site.getsitepackages() + [site.getusersitepackages()]) + os.pathsep + os.environ.get("PYTHONPATH", "")
            if binary_path.endswith(".i64") or binary_path.endswith(".idb"):
                tempidb = tempfile.NamedTemporaryFile(suffix=binary_path[-4:])
                with open(binary_path, "rb") as f:
                    tempidb.write(f.read())
                tempidb.flush()
                binary_path = tempidb.name
                command = f'"{idat_path}" -A -S"{escape_path(server_path)} {port}" -P+ "{binary_path}"'
            else:
                tempidb = tempfile.NamedTemporaryFile()
                command = f'"{idat_path}" -o"{tempidb.name}" -A -S"{escape_path(server_path)} {port}" -P+ "{binary_path}"'
            p = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            while True:
                if p.poll() is not None:
                    raise Exception(
                        f"IDA failed to start: return code {p.poll()}\n"
                        f"Command: {command}\n"
                        f"=============== STDOUT ===============\n{p.stdout.read().decode()}"
                        f"=============== STDERR ===============\n{p.stderr.read().decode()}"
                    )
                try:
                    self.conn = rpyc.connect("localhost", port, service=ForwardIO, config={"sync_request_timeout": 60*60*24})
                except:
                    continue
                break

        def exposed_import_module(self, mod):
            return self.conn.root.import_module(mod)

        def on_connect(self, conn):
            sys.stdout.write = conn.root.stdout_write
            sys.stderr.write = conn.root.stderr_write

        def on_disconnect(self, conn):
            if hasattr(self, "conn"):
                self.conn.close()
            sys.stdout = sys.__stdout__
            sys.stderr = sys.__stderr__

    return _HeadlessIdaServer
