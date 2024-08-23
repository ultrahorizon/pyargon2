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
    The string input version of the Argon2 hashing function.
    Implemented based on the definitions in RFC (https://www.ietf.org/id/draft-irtf-cfrg-argon2-10.txt).
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
    __check_params(str, password, salt, pepper, hash_len, time_cost, memory_cost,
                   parallelism, flags, variant, version, encoding)

    # Convert to Unicode
    password = password.encode('utf-8')
    salt = salt.encode('utf-8')
    pepper = pepper.encode('utf-8')

    raw_hash = __raw_hash(password, salt, pepper, hash_len, time_cost, memory_cost,
                          parallelism, flags, variant, version)

    if encoding == 'hex':
        return raw_hash.hex()
    elif encoding == 'b64':
        return base64.b64encode(raw_hash).decode('ascii')
    elif encoding == 'raw':
        return raw_hash


def hash_bytes(password: bytes, salt: bytes, pepper: bytes = b'',
               hash_len: int = DEFAULT_HASH_LENGTH,
               time_cost: int = DEFAULT_TIME_COST,
               memory_cost: int = DEFAULT_MEMORY_COST,
               parallelism: int = DEFAULT_PARALLELISM,
               flags: int = DEFAULT_FLAGS,
               variant: str = "id",
               version: int = lib.ARGON2_VERSION_NUMBER,
               encoding: str = 'hex'):
    """
    The byte array input version of the Argon2 hashing function.
    Implemented based on the definitions in RFC (https://www.ietf.org/id/draft-irtf-cfrg-argon2-10.txt).
    :param password: Password byte array.
    :param salt: Salt byte array to use for the password hash (must be unique for each hash).
    :param pepper: Optional pepper byte array to fold into the hash (keyed hashing).
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
    __check_params(bytes, password, salt, pepper, hash_len, time_cost, memory_cost,
                   parallelism, flags, variant, version, encoding)

    raw_hash = __raw_hash(password, salt, pepper, hash_len, time_cost, memory_cost,
                          parallelism, flags, variant, version)

    if encoding == 'hex':
        return raw_hash.hex()
    elif encoding == 'b64':
        return base64.b64encode(raw_hash).decode('ascii')
    elif encoding == 'raw':
        return raw_hash


def __raw_hash(password: bytes, salt: bytes, pepper: bytes = b'',
               hash_len: int = DEFAULT_HASH_LENGTH,
               time_cost: int = DEFAULT_TIME_COST,
               memory_cost: int = DEFAULT_MEMORY_COST,
               parallelism: int = DEFAULT_PARALLELISM,
               flags: int = DEFAULT_FLAGS,
               variant: str = "id",
               version: int = lib.ARGON2_VERSION_NUMBER):
    """
    The underlying raw Argon2 hashing function defined in RFC (https://www.ietf.org/id/draft-irtf-cfrg-argon2-10.txt).
    :param password: Password byte array.
    :param salt: Salt byte array to use for the password hash (must be unique for each hash).
    :param pepper: Optional pepper byte array to fold into the hash (keyed hashing).
    :param hash_len: Output length of hash in bytes.
    :param time_cost: Number of iterations to perform.
    :param memory_cost: Memory size in Kibibytes (1024 bytes).
    :param parallelism: How many independent computations chains (lanes) to run.
    :param flags: Flags to determine which fields are securely wiped.
    :param variant: Argon2 algorithm variant ('i', 'd', or 'id').
    :param version: Argon2 algorithm version number.
    :return: Hash of password in raw format.
    """
    # Create C variables
    csalt = ffi.new("uint8_t[]", salt)
    chash = ffi.new("uint8_t[]", hash_len)
    cpwd = ffi.new("uint8_t[]", password)
    if pepper:
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

    # Extract result and return raw hash
    return bytes(ffi.buffer(chash, hash_len))


def __check_params(input_type, password, salt, pepper, hash_len, time_cost, memory_cost,
                   parallelism, flags, variant, version, encoding):
    """
    Type check all input parameters before dispatching to low-level C.
    """
    if type(password) != input_type: raise ValueError('password must be of type ' + input_type.__name__)
    if type(salt) != input_type: raise ValueError('salt must be of type ' + input_type.__name__)
    if type(pepper) != input_type: raise ValueError('pepper must be of type ' + input_type.__name__)
    if type(hash_len) != int: raise ValueError('pepper must be of type int')
    if type(time_cost) != int: raise ValueError('time_cost must be of type int')
    if type(memory_cost) != int: raise ValueError('memory_cost must be of type int')
    if type(parallelism) != int: raise ValueError('parallelism must be of type int')
    if type(flags) != int: raise ValueError('flags must be of type int')
    if type(variant) != str: raise ValueError('variant must be of type str')
    if variant not in ['d', 'i', 'id']: raise ValueError(variant + ' is not a valid Argon2 variant.')
    if type(version) != int: raise ValueError('version must be of type int')
    if type(encoding) != str: raise ValueError('encoding must be of type str')
    if encoding not in ['hex', 'b64', 'raw']: raise ValueError(encoding + ' is not a valid Argon2 encoding.')
