
# run with `headless-ida /path/to/idat64 /bin/ls decompile_main.py`

import idautils, ida_funcs, ida_hexrays

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

print(decompile_function(get_function_by_name("main")))

