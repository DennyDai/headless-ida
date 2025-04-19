import importlib
import os
import site
import socket
import subprocess
import sys
import tempfile
from ctypes import cdll

import rpyc

from .helpers import ForwardIO, IDABackendType, escape_path, resolve_ida_path


def HeadlessIdaServer(idat_path):
    backend_type, ida_path = resolve_ida_path(idat_path)

    class _HeadlessIdaServer(rpyc.Service):
        def exposed_init(self, binary):
            if backend_type == IDABackendType.IDALIB:
                return self._idalib_backend(ida_path, binary)
            elif backend_type in [IDABackendType.IDA, IDABackendType.IDAT]:
                return self._ida_backend(ida_path, binary)

        def _idalib_backend(self, idalib_path, binary):
            sys.path.insert(
                0, os.path.join(os.path.dirname(idalib_path), "python/3/ida_64")
            )
            sys.path.insert(1, os.path.join(os.path.dirname(idalib_path), "python/3"))
            self.libida = cdll.LoadLibrary(idalib_path)
            self.libida.init_library(0, None)
            binary_file = tempfile.NamedTemporaryFile(delete=False)
            binary_file.write(binary)
            binary_file.flush()
            binary_file.close()
            self.libida.open_database(str(binary_file.name).encode(), True)

        def _ida_backend(self, idat_path, binary):
            binary_file = tempfile.NamedTemporaryFile(delete=False)
            binary_file.write(binary)
            binary_file.flush()
            binary_file.close()
            binary_path = binary_file.name

            server_path = os.path.join(
                os.path.realpath(os.path.dirname(__file__)), "ida_script.py"
            )
            port = 8000
            with socket.socket() as s:
                s.bind(("", 0))
                port = s.getsockname()[1]
            os.environ["PYTHONPATH"] = (
                os.pathsep.join(site.getsitepackages() + [site.getusersitepackages()])
                + os.pathsep
                + os.environ.get("PYTHONPATH", "")
            )
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
            p = subprocess.Popen(
                command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE
            )
            while True:
                if p.poll() is not None:
                    raise Exception(
                        f"IDA failed to start: return code {p.poll()}\n"
                        f"Command: {command}\n"
                        f"=============== STDOUT ===============\n{p.stdout.read().decode()}"
                        f"=============== STDERR ===============\n{p.stderr.read().decode()}"
                    )
                try:
                    self.conn = rpyc.connect(
                        "localhost",
                        port,
                        service=ForwardIO,
                        config={"sync_request_timeout": 60 * 60 * 24},
                    )
                except:
                    continue
                break

        def exposed_import_module(self, mod):
            # return self.conn.root.import_module(mod)
            if hasattr(self, "conn"):
                return self.conn.root.import_module(mod)
            else:
                return importlib.import_module(mod)

        def on_connect(self, conn):
            sys.stdout.write = conn.root.stdout_write
            sys.stderr.write = conn.root.stderr_write

        def on_disconnect(self, conn):
            if hasattr(self, "libida"):
                self.libida.close_database()
            if hasattr(self, "conn"):
                self.conn.close()
            sys.stdout = sys.__stdout__
            sys.stderr = sys.__stderr__

    return _HeadlessIdaServer
