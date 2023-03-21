import idautils, ida_name

for func in idautils.Functions():
    print(f"{hex(func)} {ida_name.get_ea_name(func)}")
