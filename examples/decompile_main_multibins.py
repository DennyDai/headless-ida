from headless_ida import HeadlessIda

IDAT_PATH = "/path/to/idat64"


class IDA:
    def __init__(self, binary_path):
        self.headless_ida = HeadlessIda(IDAT_PATH, binary_path)
        self.idautils = self.headless_ida.import_module("idautils")
        self.ida_funcs = self.headless_ida.import_module("ida_funcs")
        self.ida_hexrays = self.headless_ida.import_module("ida_hexrays")

    def get_function_by_name(self, name):
        for ea in self.idautils.Functions():
            if self.ida_funcs.get_func_name(ea) == name:
                return ea
        return None

    def decompile_function(self, ea):
        cfunc = self.ida_hexrays.decompile(ea)
        if cfunc is None:
            return None
        return str(cfunc)


ls = IDA("/bin/ls")
cat = IDA("/bin/cat")

print(ls.decompile_function(ls.get_function_by_name("main")))
print(cat.decompile_function(cat.get_function_by_name("main")))
