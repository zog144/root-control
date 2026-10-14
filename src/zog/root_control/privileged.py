import ctypes
import ctypes.util
import os

libc_name = ctypes.util.find_library("c")
if not libc_name:
    raise RuntimeError("libc could not be located")
libc = ctypes.CDLL(libc_name, use_errno=True)

libc.mount.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_ulong, ctypes.c_void_p]
libc.mount.restype = ctypes.c_int
libc.umount2.argtypes = [ctypes.c_char_p, ctypes.c_int]
libc.umount2.restype = ctypes.c_int

def mount(source, target, filesystem, flags=0, data=None):
    result = libc.mount(
        source.encode(), target.encode(), filesystem.encode(), flags,
        None if data is None else ctypes.c_char_p(data.encode())
    )
    if result:
        errno = ctypes.get_errno()
        raise OSError(errno, os.strerror(errno), target)

def unmount(target, flags=0):
    result = libc.umount2(target.encode(), flags)
    if result:
        errno = ctypes.get_errno()
        raise OSError(errno, os.strerror(errno), target)
