
# run with `headless-ida /path/to/idat64 /bin/ls list_strings.py`

import idautils

for string in idautils.Strings():
    print(f"\033[92m{hex(string.ea)}\033[0m", end="\t")
    print(f"\033[93m{str(string).encode()}\033[0m", end="\t")
    print(f"\033[94m{[hex(ref) for ref in idautils.DataRefsTo(string.ea)]}\033[0m")
