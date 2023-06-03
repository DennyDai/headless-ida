
# run with `headless-ida /path/to/idat64 /bin/ls list_functions.py`

import idautils, ida_name

for func in idautils.Functions():
    print(f"{hex(func)} {ida_name.get_ea_name(func)}")
