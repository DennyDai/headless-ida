import rpyc
import importlib
import ida_auto
import ida_loader
import ida_pro
import idc
import sys

class HeadlessIda(rpyc.Service):
    def __init__(self):
        super().__init__()
        ida_auto.auto_wait()

    def on_connect(self, conn):
        ida_loader.set_database_flag(ida_loader.DBFL_KILL)
        sys.stdout.write = conn.root.stdout_write
        sys.stderr.write = conn.root.stderr_write

    def on_disconnect(self, conn):
        ida_pro.qexit(0)
        sys.stdout = sys.__stdout__
        sys.stderr = sys.__stderr__

    def exposed_import_module(self, mod):
        return importlib.import_module(mod)


if __name__ == "__main__":
    t = rpyc.utils.server.OneShotServer(HeadlessIda, port=int(
        idc.ARGV[1]), protocol_config={"allow_all_attrs": True})
    t.start()
