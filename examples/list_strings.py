import os
from headless_ida import HeadlessIda

headlessida = HeadlessIda(os.getenv("IDAT_PATH"), "./ls")

idautils = headlessida.import_module("idautils")
ida_funcs = headlessida.import_module("ida_funcs")
ida_name = headlessida.import_module("ida_name")

def search_string(search):
    result = {}
    for string in idautils.Strings():
        if search in str(string):
            result[string.ea] = str(string)
    return result

def get_string_references(ea):
    result = []
    for ref in idautils.DataRefsTo(ea):
        result.append(ref)
    return result

for ea, string in search_string("Usage:").items():
    print(f"{hex(ea)} {string.encode('utf-8')}")
    print(f"References: ")
    for ref in get_string_references(ea):
        func = ida_funcs.get_func(ref)
        if func:
            print(f"\t{hex(func.start_ea)} {ida_name.get_ea_name(func.start_ea)}")
