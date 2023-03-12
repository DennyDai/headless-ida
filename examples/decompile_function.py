import os
from headless_ida import HeadlessIda

headlessida = HeadlessIda(os.getenv("IDAT_PATH"), "./ls")

idautils = headlessida.import_module("idautils")
ida_hexrays = headlessida.import_module("ida_hexrays")
ida_funcs = headlessida.import_module("ida_funcs")

def get_function_by_name(name):
    for ea in idautils.Functions():
        if ida_funcs.get_func_name(ea) == name:
            return ea
    return None

def decompile_function(ea):
    cfunc = ida_hexrays.decompile(ea)
    if cfunc is None:
        return None
    return str(cfunc)

print(decompile_function(get_function_by_name("sub_15AA0")))

