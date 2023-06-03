<p align="center">
  <img alt="Headless IDA" src="https://raw.githubusercontent.com/DennyDai/headless-ida/main/headless-ida.png" width="128">
</p>
<h1 align="center">Headless IDA</h1>

[![Latest Release](https://img.shields.io/pypi/v/headless-ida.svg)](https://pypi.python.org/pypi/headless-ida/)
[![PyPI Statistics](https://img.shields.io/pypi/dm/headless-ida.svg)](https://pypistats.org/packages/headless-ida)
[![License](https://img.shields.io/github/license/DennyDai/headless-ida.svg)](https://github.com/DennyDai/headless-ida/blob/main/LICENSE)

# Install
```bash
pip install headless-ida
```

# Usage

### Use it as a normal Python module.
```python
# Initialize HeadlessIda
from headless_ida import HeadlessIda
headlessida = HeadlessIda("/path/to/idat64", "/path/to/binary")

# Import IDA Modules (make sure you have initialized HeadlessIda first)
import idautils
import ida_name

# Or Import All IDA Modules at Once (idaapi is not imported by default)
# from headless_ida.ida_headers import *

# Have Fun
for func in idautils.Functions():
    print(f"{hex(func)} {ida_name.get_ea_name(func)}")
```

### Use it as a command line tool.
```bash
# Interactive Console
$ headless-ida /path/to/idat64 /path/to/binary
Python 3.8.10 (default, Nov 14 2022, 12:59:47) 
[GCC 9.4.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
(InteractiveConsole)
>>> import idautils
>>> list(idautils.Functions())[0:10]
[16384, 16416, 16432, 16448, 16464, 16480, 16496, 16512, 16528, 16544]
>>> 


# Run IDAPython Script
$ headless-ida /path/to/idat64 /path/to/binary idascript.py


# One-liner
$ headless-ida /path/to/idat64 /path/to/binary -c "import idautils; print(list(idautils.Functions())[0:10])"


# In case you like IPython
$ headless-ida /path/to/idat64 /path/to/binary -c "import IPython; IPython.embed();"
```

# Advanced Usage
## Remote Server

### Start a Headless IDA server
```bash
$ headless-ida-server /path/to/idat64 localhost 1337 &
```

### Connect to the server in Python script
```python
# Initialize HeadlessIda
from headless_ida import HeadlessIdaRemote
headlessida = HeadlessIdaRemote("localhost", 1337, "/path/to/local/binary")

# Import IDA Modules (make sure you have initialized HeadlessIda first)
import idautils
import ida_name

# Have Fun
for func in idautils.Functions():
    print(f"{hex(func)} {ida_name.get_ea_name(func)}")
```

### Connect to the server in command line
```bash
# Interactive Console
$ headless-ida localhost:1337 /path/to/local/binary
# Run IDAPython Script
$ headless-ida localhost:1337 /path/to/local/binary idascript.py
# One-liner
$ headless-ida localhost:1337 /path/to/local/binary -c "import idautils; print(list(idautils.Functions())[0:10])"
```


# Resources
- [Headless IDA Examples](https://github.com/DennyDai/headless-ida/tree/main/examples)
- [IDAPython Official Documentation](https://www.hex-rays.com/products/ida/support/idapython_docs/)
- [IDAPython Official Examples](https://github.com/idapython/src/tree/master/examples)

# Known Issues
### `from XXX import *`
 - Using `from XXX import *` syntax with certain ida modules (like idaapi, ida_ua, etc.) is currently unsupported due to SWIG and RPyC compatibility issues. We recommend importing specific items with `from XXX import YYY, ZZZ`, or importing the entire module using `import XXX`.
 - The issue arises because SWIG, employed for creating Python bindings for C/C++ code, generates intermediary objects (SwigVarlink) that RPyC, our remote procedure call mechanism, cannot serialize or transmit correctly.
