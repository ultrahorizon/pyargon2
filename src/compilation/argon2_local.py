import os
import platform

from classes.FFI import FFI

ffi = FFI()

# Define the sources
lib_base = '../extern/argon2/src'
include_dirs = [os.path.join(lib_base, '../include')]
optimized = platform.machine() in ("i686", "x86", "x86_64", "AMD64")

ffi.set_source(
    "_argon2", "#include <argon2.h>",
    include_dirs=include_dirs,
    sources=[
        os.path.join(lib_base, path) for path in [
            "argon2.c",
            "core.c",
            "blake2/blake2b.c",
            "thread.c",
            "encoding.c",
            "opt.c" if optimized else "ref.c"
        ]
    ],
)

if __name__ == "__main__":
    ffi.compile(verbose=True)
