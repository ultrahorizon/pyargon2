from setuptools import find_packages, setup

setup(
    packages=find_packages(),
    ext_package="pyargon2",
    zip_safe=False,

    # Compile C extensions
    cffi_modules=["pyargon2/_compiler.py:ffi"],
)
