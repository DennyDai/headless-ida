import rpyc
import socket
import os
import subprocess
import builtins
import tempfile
import site

from .helpers import escape_path, ForwardIO


class HeadlessIda():
    IDA_MODULES = ["ida_allins", "ida_auto",
                   "ida_bitrange", "ida_bytes",
                   "ida_dbg", "ida_dirtree", "ida_diskio",
                   "ida_entry", "ida_enum", "ida_expr",
                   "ida_fixup", "ida_fpro", "ida_frame", "ida_funcs",
                   "ida_gdl", "ida_graph",
                   "ida_hexrays",
                   "ida_ida", "ida_idaapi", "ida_idc", "ida_idd", "ida_idp", "ida_ieee",
                   "ida_kernwin",
                   "ida_lines", "ida_loader",
                   "ida_merge", "ida_mergemod", "ida_moves",
                   "ida_nalt", "ida_name", "ida_netnode",
                   "ida_offset",
                   "ida_pro", "ida_problems",
                   "ida_range", "ida_registry",
                   "ida_search", "ida_segment", "ida_segregs", "ida_srclang", "ida_strlist", "ida_struct",
                   "ida_tryblks", "ida_typeinf",
                   "ida_ua",
                   "ida_xref",
                   "idc", "idautils",
                   "idaapi",
                   ]

    def __init__(self, idat_path, binary_path, override_import=True):
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
        return self.conn.root.import_module(mod)

    def __del__(self):
        if hasattr(self, "conn"):
            self.conn.close()


class HeadlessIdaRemote(HeadlessIda):
    def __init__(self, host, port, binary_path, override_import=True):
        self.conn = rpyc.connect(host, int(port), service=ForwardIO, config={"sync_request_timeout": 60*60*24})
        with open(binary_path, "rb") as f:
            self.conn.root.init(f.read())
        if override_import:
            self.override_import()
