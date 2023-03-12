from headless_ida import HeadlessIda
headlessida = HeadlessIda("/path/to/idat64", "/path/to/binary")

idautils = headlessida.import_module("idautils")
ida_name = headlessida.import_module("ida_name")

for func in idautils.Functions():
    print(f"{hex(func)} {ida_name.get_ea_name(func)}")
