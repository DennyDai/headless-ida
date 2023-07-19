import os
import ctypes


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
        return f"\\\"{path}\\\""
