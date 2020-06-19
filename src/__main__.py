from _argon2 import ffi, lib


# These parameters should be increased regularly
DEFAULT_RANDOM_SALT_LENGTH = 16
DEFAULT_HASH_LENGTH = 32
DEFAULT_TIME_COST = 2
DEFAULT_MEMORY_COST = 512
DEFAULT_PARALLELISM = 4
DEFAULT_PARAMETER_THRESHOLD = 4
DEFAULT_FLAGS = lib.ARGON2_FLAG_CLEAR_PASSWORD | lib.ARGON2_FLAG_CLEAR_SECRET


def hash(password=None, salt=None, secret=None, hash_len=DEFAULT_HASH_LENGTH, time_cost=DEFAULT_TIME_COST,
         memory_cost=DEFAULT_MEMORY_COST, parallelism=DEFAULT_PARALLELISM, flags=DEFAULT_FLAGS,
         version=lib.ARGON2_VERSION_NUMBER):
    csalt = ffi.new("uint8_t[]", salt)
    chash = ffi.new("uint8_t[]", hash_len)
    cpwd = ffi.new("uint8_t[]", password.encode('utf-8'))

    if secret:
        csecret = ffi.new("uint8_t[]", secret)
        secret_len = len(secret)
    else:
        csecret = ffi.NULL
        secret_len = 0

    ctx = ffi.new("argon2_context *", dict(
        version=version,
        out=chash, outlen=hash_len,
        pwd=cpwd, pwdlen=len(password),
        salt=csalt, saltlen=len(salt),
        secret=csecret, secretlen=secret_len,
        ad=ffi.NULL, adlen=0,
        t_cost=time_cost,
        m_cost=memory_cost,
        lanes=parallelism, threads=parallelism,
        allocate_cbk=ffi.NULL, free_cbk=ffi.NULL,
        flags=flags,
    ))

    rc = lib.argon2_ctx(ctx, lib.Argon2_i)
    raw_hash = bytes(ffi.buffer(chash, hash_len))
    print(raw_hash)
    print(rc)

import os
hash(password='test', salt=os.urandom(16))
