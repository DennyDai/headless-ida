import ctypes
import importlib
import os
import shutil
import site
import socket
import subprocess
import sys
import tempfile

import rpyc

from .helpers import ForwardIO, IDABackendType, escape_path, resolve_ida_path


def HeadlessIdaServer(idat_path):
    backend_type, ida_path = resolve_ida_path(idat_path)
    
    # Check if trying to use idalib with the server
    if backend_type == IDABackendType.IDALIB:
        raise RuntimeError(
            "idalib cannot be used with server mode (requires main thread). "
            "Use regular IDA instead: headless-ida-server /path/to/idat host port"
        )

    class _HeadlessIdaServer(rpyc.Service):
        def exposed_init(self, binary, ftype=None, processor=None):
            if backend_type == IDABackendType.IDALIB:
                return self._idalib_backend(ida_path, binary, ftype=ftype, processor=processor)
            elif backend_type in [IDABackendType.IDA, IDABackendType.IDAT]:
                return self._ida_backend(ida_path, binary, ftype=ftype, processor=processor)

        def _idalib_backend(self, idalib_path, binary, ftype=None, processor=None):
            # This should never be reached due to the check in HeadlessIdaServer()
            # but keeping as a safety check
            self.libida = ctypes.cdll.LoadLibrary(idalib_path)
            self.libida.init_library(0, None)
            
            # check if get_library_version is available
            if not hasattr(self.libida, "get_library_version"):
                major, minor, build = 9, 0, 0
            else:
                major, minor, build = ctypes.c_int(), ctypes.c_int(), ctypes.c_int()
                self.libida.get_library_version(
                    ctypes.byref(major), ctypes.byref(minor), ctypes.byref(build)
                )
                major, minor, build = major.value, minor.value, build.value
            
            if major == 9 and minor == 0:
                sys.path.insert(
                    0, os.path.join(os.path.dirname(idalib_path), "python/3/ida_64")
                )
                sys.path.insert(1, os.path.join(os.path.dirname(idalib_path), "python/3"))
            else:
                sys.path.insert(
                    0, os.path.join(os.path.dirname(idalib_path), "python/lib-dynload")
                )
                sys.path.insert(1, os.path.join(os.path.dirname(idalib_path), "python"))
            
            # Create temp directory and save binary
            tempdir = tempfile.mkdtemp()
            binary_file = os.path.join(tempdir, "temp_binary")
            with open(binary_file, 'wb') as f:
                f.write(binary)
            
            if major == 9 and minor == 0:
                self.libida.open_database(
                    str(binary_file).encode(),
                    True,
                )
            else:
                ida_args = []
                if processor is not None:
                    ida_args.append(f'-p{processor}')
                if ftype is not None:
                    ida_args.append(f'-T{ftype}')
                if ida_args:
                    cmd_line = ' '.join(ida_args)
                    self.libida.open_database(
                        str(binary_file).encode(),
                        True,
                        cmd_line.encode(),
                    )
                else:
                    self.libida.open_database(
                        str(binary_file).encode(),
                        True,
                        None,
                    )

        def _ida_backend(self, idat_path, binary, ftype=None, processor=None):
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
                command = f'"{idat_path}" -A -S"{escape_path(server_path)} {port}" -P+'
                if ftype is not None:
                    command += f' -T "{ftype}"'
                if processor is not None:
                    command += f' -p{processor}'
                command += f' "{binary_path}"'
            else:
                tempidb = tempfile.NamedTemporaryFile()
                command = f'"{idat_path}" -o"{tempidb.name}" -A -S"{escape_path(server_path)} {port}"'
                if ftype is not None:
                    command += f' -T "{ftype}"'
                if processor is not None:
                    command += f' -p{processor}'
                command += f' "{binary_path}"'
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
