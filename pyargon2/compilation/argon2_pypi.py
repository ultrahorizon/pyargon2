# THIS FILE IS TO BE CALLED BY PYPI's setup.py SCRIPT ONLY

import os

from pyargon2.classes.FFI import FFI

# Define the sources
include_dirs = ['extern/argon2/include']

ffi = FFI()
ffi.set_source(
    "_ffi", "#include <argon2.h>",
    include_dirs=include_dirs,
    libraries=["argon2"],
)

if __name__ == '__main__':
    ffi.compile()
