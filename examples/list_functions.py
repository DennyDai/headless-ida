from headless_ida import HeadlessIda
headlessida = HeadlessIda("/path/to/idat64", "/path/to/binary")
idautils = headlessida.import_module("idautils")

print([x for x in idautils.Functions()])
