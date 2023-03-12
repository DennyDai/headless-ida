import rpyc
import importlib
import ida_loader
import ida_pro
import idc


class HeadlessIda(rpyc.Service):
    def on_disconnect(self, conn):
        ida_loader.set_database_flag(ida_loader.DBFL_KILL)
        ida_pro.qexit(0)

    def exposed_import_module(self, mod):
        return importlib.import_module(mod)


if __name__ == "__main__":
    t = rpyc.utils.server.OneShotServer(HeadlessIda, port=int(
        idc.ARGV[1]), protocol_config={"allow_all_attrs": True})
    t.start()
