import rpyc
import socket
import os
import subprocess
import tempfile

from .helpers import escape_path


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
            tempidb = tempfile.NamedTemporaryFile(suffix=".idb")
            p = subprocess.Popen(
                f'{idat_path} -o"{tempidb.name}" -A -S"{escape_path(server_path)} {port}" -P+ {binary_path}', shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            while True:
                if p.poll() is not None:
                    raise Exception(
                        f"IDA failed to start: return code {p.poll()}\n"
                        f"=============== STDOUT ===============\n{p.stdout.read().decode()}"
                        f"=============== STDERR ===============\n{p.stderr.read().decode()}"
                    )
                try:
                    self.conn = rpyc.connect("localhost", port)
                except:
                    continue
                break

        def exposed_import_module(self, mod):
            return self.conn.root.import_module(mod)

        def on_disconnect(self, conn):
            if hasattr(self, "conn"):
                self.conn.close()
    return _HeadlessIdaServer
