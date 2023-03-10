import os
from headless_ida import HeadlessIda

headlessida = HeadlessIda(os.getenv("IDAT_PATH"), "./ls")

idautils = headlessida.import_module("idautils")
ida_name = headlessida.import_module("ida_name")

for func in idautils.Functions():
    print(f"{hex(func)} {ida_name.get_ea_name(func)}")
