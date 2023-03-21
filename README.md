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
```python
# Initialize HeadlessIda
from headless_ida import HeadlessIda
headlessida = HeadlessIda("/path/to/idat64", "/path/to/binary")

# Import IDA Modules (make sure you have initialized HeadlessIda first)
import idautils
import ida_name

# Have Fun
for func in idautils.Functions():
    print(f"{hex(func)} {ida_name.get_ea_name(func)}")
```

# Resources
- [Headless IDA Examples](https://github.com/DennyDai/headless-ida/tree/main/examples)
- [IDAPython Documentation](https://www.hex-rays.com/products/ida/support/idapython_docs/)
