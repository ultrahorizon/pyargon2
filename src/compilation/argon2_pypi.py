# THIS FILE IS TO BE CALLED BY PYPI's setup.py SCRIPT ONLY

import os

from classes.FFI import FFI

# Define the sources
lib_base = '../extern/argon2/src'
include_dirs = [os.path.join(lib_base, '../include')]

ffi = FFI()
ffi.set_source(
    "_ffi", "#include <argon2.h>",
    include_dirs=include_dirs,
    libraries=["_argon2"],
)

if __name__ == '__main__':
    ffi.compile()
