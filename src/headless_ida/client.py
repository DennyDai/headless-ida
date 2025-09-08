import atexit
import builtins
import ctypes
import os
import shutil
import site
import socket
import subprocess
import sys
import importlib
import tempfile
from typing import Optional

import rpyc

from .helpers import ForwardIO, IDABackendType, escape_path, resolve_ida_path


class HeadlessIda:
    IDA_MODULES = [
        "ida_allins",
        "ida_auto",
        "ida_bitrange",
        "ida_bytes",
        "ida_dbg",
        "ida_dirtree",
        "ida_diskio",
        "ida_entry",
        "ida_enum",
        "ida_expr",
        "ida_fixup",
        "ida_fpro",
        "ida_frame",
        "ida_funcs",
        "ida_gdl",
        "ida_graph",
        "ida_hexrays",
        "ida_ida",
        "ida_idaapi",
        "ida_idc",
        "ida_idd",
        "ida_idp",
        "ida_ieee",
        "ida_kernwin",
        "ida_lines",
        "ida_loader",
        "ida_merge",
        "ida_mergemod",
        "ida_moves",
        "ida_nalt",
        "ida_name",
        "ida_netnode",
        "ida_offset",
        "ida_pro",
        "ida_problems",
        "ida_range",
        "ida_registry",
        "ida_search",
        "ida_segment",
        "ida_segregs",
        "ida_srclang",
        "ida_strlist",
        "ida_struct",
        "ida_tryblks",
        "ida_typeinf",
        "ida_ua",
        "ida_xref",
        "idc",
        "idautils",
        "idaapi",
    ]

    def __init__(
        self,
        ida_dir,
        binary_path,
        override_import=True,
        bits=64,
        ftype: Optional[str] = None,
        processor: Optional[str] = None,
    ) -> None:
        self.backend_type, self.ida_path = resolve_ida_path(ida_dir, bits)
        self.cleaned_up = False
        atexit.register(self.clean_up)

        if self.backend_type == IDABackendType.IDALIB:
            return self._idalib_backend(
                self.ida_path, binary_path, override_import, ftype=ftype, processor=processor
            )
        elif self.backend_type in [IDABackendType.IDA, IDABackendType.IDAT]:
            return self._ida_backend(
                self.ida_path, binary_path, override_import, ftype=ftype, processor=processor
            )

    def _idalib_backend(
        self,
        idalib_path,
        binary_path,
        override_import=True,
        ftype: Optional[str] = None,
        processor: Optional[str] = None,
    ):
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

        # TODO: idalib doesn't support saving database to other location, so we need to copy the file manually
        tempdir = tempfile.mkdtemp()
        shutil.copy(binary_path, tempdir)
        
        target_file = os.path.join(tempdir, os.path.basename(binary_path))

        if major == 9 and minor == 0:
            self.libida.open_database(
                str(target_file).encode(),
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
                    str(target_file).encode(),
                    True,
                    cmd_line.encode(),
                )
            else:
                self.libida.open_database(
                    str(target_file).encode(),
                    True,
                    None,
                )

    def _ida_backend(
        self, idat_path, binary_path, override_import=True, ftype: Optional[str] = None, processor: Optional[str] = None
    ) -> None:
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
            except Exception:
                continue
            break

        if override_import:
            self.override_import()

    def override_import(self):
        original_import = builtins.__import__

        def ida_import(name, *args, **kwargs):
            if name in self.IDA_MODULES:
                return self.import_module(name)
            return original_import(name, *args, **kwargs)

        builtins.__import__ = ida_import

    def import_module(self, mod):
        if hasattr(self, "libida"):
            return importlib.import_module(mod)
        if hasattr(self, "conn"):
            return self.conn.root.import_module(mod)
        else:
            raise RuntimeError("No IDA backend initialized")

    def clean_up(self):
        if self.cleaned_up:
            return
        if hasattr(self, "libida"):
            self.libida.close_database(True)
        if hasattr(self, "conn"):
            self.conn.close()
        self.cleaned_up = True

    def __del__(self):
        self.clean_up()


class HeadlessIdaRemote(HeadlessIda):
    def __init__(self, host, port, binary_path, override_import=True, ftype=None, processor=None):
        self.cleaned_up = False
        atexit.register(self.clean_up)
        self.conn = rpyc.connect(
            host,
            int(port),
            service=ForwardIO,
            config={"sync_request_timeout": 60 * 60 * 24},
        )
        with open(binary_path, "rb") as f:
            self.conn.root.init(f.read(), ftype=ftype, processor=processor)
        if override_import:
            self.override_import()
