import base64

from ._argon2 import ffi, lib

import pyargon2.classes.errors as errors

# These parameters should be increased regularly
DEFAULT_HASH_LENGTH = 32
DEFAULT_TIME_COST = 620
DEFAULT_MEMORY_COST = 4096
DEFAULT_PARALLELISM = 8
DEFAULT_FLAGS = lib.ARGON2_FLAG_CLEAR_PASSWORD | lib.ARGON2_FLAG_CLEAR_SECRET


def hash(password: str, salt: str, pepper: str = "",
         hash_len: int = DEFAULT_HASH_LENGTH,
         time_cost: int = DEFAULT_TIME_COST,
         memory_cost: int = DEFAULT_MEMORY_COST,
         parallelism: int = DEFAULT_PARALLELISM,
         flags: int = DEFAULT_FLAGS,
         variant: str = "id",
         version: int = lib.ARGON2_VERSION_NUMBER,
         encoding: str = 'hex'):
    """
    The Argon2 hashing function defined in draft RFC (https://www.ietf.org/id/draft-irtf-cfrg-argon2-10.txt).
    :param password: Password string.
    :param salt: Salt string to use for the password hash (must be unique for each hash).
    :param pepper: Optional pepper string to fold into the hash (keyed hashing).
    :param hash_len: Output length of hash in bytes.
    :param time_cost: Number of iterations to perform.
    :param memory_cost: Memory size in Kibibytes (1024 bytes).
    :param parallelism: How many independent computations chains (lanes) to run.
    :param flags: Flags to determine which fields are securely wiped.
    :param variant: Argon2 algorithm variant ('i', 'd', or 'id').
    :param version: Argon2 algorithm version number.
    :param encoding: Encoding for the returned hash type ('raw', 'hex' or 'b64').
    :return: Hash of password in format specified by the 'encoding' parameter.
    """
    # Check types of all parameters before proceeding
    _check_params(password, salt, pepper, hash_len, time_cost, memory_cost,
                  parallelism, flags, variant, version, encoding)

    # Convert to Unicode
    password = password.encode('utf-8')
    salt = salt.encode('utf-8')

    # Create C variables
    csalt = ffi.new("uint8_t[]", salt)
    chash = ffi.new("uint8_t[]", hash_len)
    cpwd = ffi.new("uint8_t[]", password)
    if pepper:
        pepper = pepper.encode('utf-8')
        csecret = ffi.new("uint8_t[]", pepper)
        secret_len = len(pepper)
    else:
        csecret = ffi.NULL
        secret_len = 0

    # Build argon2 ctx
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

    # Execute the hashing function in C
    rc = lib.argon2_ctx(ctx, {
        'i': lib.Argon2_i,
        'd': lib.Argon2_d,
        'id': lib.Argon2_id,
    }[variant])
    # Check return code and report error if necessary
    if rc != 0:
        raise errors.Argon2Error(errors.Argon2ErrorCode(rc).name)

    # Extract result and return in appropriate format
    raw_hash = bytes(ffi.buffer(chash, hash_len))
    if encoding == 'hex':
        return raw_hash.hex()
    elif encoding == 'b64':
        return base64.b64encode(raw_hash).decode('ascii')
    elif encoding == 'raw':
        return raw_hash


def _check_params(password, salt, pepper, hash_len, time_cost, memory_cost,
                  parallelism, flags, variant, version, encoding):
    """
    Type check all input parameters before dispatching to low-level C.
    """
    if type(password) != str: raise ValueError('password must be of string type')
    if type(salt) != str: raise ValueError('salt must be of string type')
    if type(pepper) != str: raise ValueError('pepper must be of string type')
    if type(hash_len) != int: raise ValueError('pepper must be of integer type')
    if type(time_cost) != int: raise ValueError('time_cost must be of integer type')
    if type(memory_cost) != int: raise ValueError('memory_cost must be of integer type')
    if type(parallelism) != int: raise ValueError('parallelism must be of integer type')
    if type(flags) != int: raise ValueError('flags must be of integer type')
    if type(variant) != str: raise ValueError('variant must be of string type')
    if variant not in ['d', 'i', 'id']: raise ValueError(variant + ' is not a valid Argon2 variant.')
    if type(version) != int: raise ValueError('version must be of integer type')
    if type(encoding) != str: raise ValueError('encoding must be of string type')
    if encoding not in ['hex', 'b64', 'raw']: raise ValueError(encoding + ' is not a valid Argon2 encoding.')
