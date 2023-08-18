
# run with `headless-ida /path/to/idat64 /bin/ls save_idb.py`

import ida_loader

ida_loader.save_database("/tmp/ls.idb", 0)

