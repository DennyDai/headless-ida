import ctypes
import os
import platform
import sys
from enum import Enum, auto

import rpyc


class ForwardIO(rpyc.Service):
    def exposed_stdout_write(self, data):
        print(data, end="", file=sys.stdout)

    def exposed_stderr_write(self, data):
        print(data, end="", file=sys.stderr)


def escape_path(path):
    if os.name == "nt":
        _GetShortPathName = ctypes.windll.kernel32.GetShortPathNameW
        _GetShortPathName.argtypes = [ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_uint]
        _GetShortPathName.restype = ctypes.c_uint

        buffer = ctypes.create_unicode_buffer(len(path) + 1)
        if _GetShortPathName(path, buffer, len(buffer)):
            return buffer.value
        else:
            raise Exception("Failed to get short path")
    else:
        return f'\\"{path}\\"'


class IDABackendType(Enum):
    IDA = auto()
    IDAT = auto()
    IDALIB = auto()


def resolve_ida_path(path, bits=64):
    IDA_BINARIES = {
        "Windows": {
            "idalib": ["idalib64.dll", "idalib.dll"],
            "ida": ["ida64.exe", "ida.exe"],
            "idat": ["idat64.exe", "idat.exe"],
        },
        "Linux": {
            "idalib": ["libidalib64.so", "libidalib.so"],
            "ida": ["ida64", "ida"],
            "idat": ["idat64", "idat"],
        },
        "Darwin": {
            "idalib": ["libidalib64.dylib", "libidalib.dylib"],
            "ida": ["ida64", "ida"],
            "idat": ["idat64", "idat"],
        },
    }

    system = platform.system()
    if system not in IDA_BINARIES:
        raise ValueError(f"Unsupported platform: {system}")

    binaries = IDA_BINARIES[system]

    if os.path.isfile(path):
        filename = os.path.basename(path)
        if filename in binaries["idalib"]:
            return IDABackendType.IDALIB, path
        if filename in binaries["ida"]:
            return IDABackendType.IDA, path
        if filename in binaries["idat"]:
            return IDABackendType.IDAT, path

    elif os.path.isdir(path):
        # Check for idalib variants
        for idalib_binary in binaries["idalib"]:
            idalib_path = os.path.join(path, idalib_binary)
            if os.path.exists(idalib_path):
                return IDABackendType.IDALIB, idalib_path

        idat_binary = binaries["idat"][0 if bits == 64 else 1]
        idat_path = os.path.join(path, idat_binary)
        if os.path.exists(idat_path):
            return IDABackendType.IDAT, idat_path

        ida_binary = binaries["ida"][0 if bits == 64 else 1]
        ida_path = os.path.join(path, ida_binary)
        if os.path.exists(ida_path):
            return IDABackendType.IDA, ida_path

    raise ValueError(f"Invalid IDA path: {path}")
