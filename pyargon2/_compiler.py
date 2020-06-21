import os
import platform

from cffi import FFI

# Create the FFI object and define useful variables
ffi = FFI()
lib_base = 'extern/argon2/src'
include_dirs = ['extern/argon2/include']
optimized = platform.machine() in ("i686", "x86", "x86_64", "AMD64")

# Cherry pick C definitions from library
ffi.cdef("""
        /* ARGON2 FLAGS */
        #define ARGON2_FLAG_CLEAR_PASSWORD ...
        #define ARGON2_FLAG_CLEAR_SECRET ...
        #define ARGON2_DEFAULT_FLAGS ...
        
        /* Memory allocator types --- for external allocation */
        typedef int (*allocate_fptr)(uint8_t **memory, size_t bytes_to_allocate);
        typedef void (*deallocate_fptr)(uint8_t *memory, size_t bytes_to_allocate);
        
        /* Argon2 algorithm type */
        typedef enum Argon2_type {
          Argon2_d = 0,
          Argon2_i = 1,
          Argon2_id = 2
        } argon2_type;
        
        /* Version of the algorithm */
        typedef enum Argon2_version {
            ARGON2_VERSION_10 = 0x10,
            ARGON2_VERSION_13 = 0x13,
            ARGON2_VERSION_NUMBER = ARGON2_VERSION_13
        } argon2_version;
        
        /* Argon2 Low-level context type */
        typedef struct Argon2_Context {
            uint8_t *out;    /* output array */
            uint32_t outlen; /* digest length */
        
            uint8_t *pwd;    /* password array */
            uint32_t pwdlen; /* password length */
        
            uint8_t *salt;    /* salt array */
            uint32_t saltlen; /* salt length */
        
            uint8_t *secret;    /* key array */
            uint32_t secretlen; /* key length */
        
            uint8_t *ad;    /* associated data array */
            uint32_t adlen; /* associated data length */
        
            uint32_t t_cost;  /* number of passes */
            uint32_t m_cost;  /* amount of memory requested (KB) */
            uint32_t lanes;   /* number of lanes */
            uint32_t threads; /* maximum number of threads */
        
            uint32_t version; /* version number */
        
            allocate_fptr allocate_cbk; /* pointer to memory allocator */
            deallocate_fptr free_cbk;   /* pointer to memory deallocator */
        
            uint32_t flags; /* array of bool options */
        } argon2_context;
        
        /* Low level context execution function */
        int argon2_ctx(argon2_context *context, argon2_type type);""")

# Define the module name and sources that will be compiled into the extension
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
