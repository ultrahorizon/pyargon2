from setuptools import find_packages, setup

setup(
    name='pyargon2',
    version='0.2.0',
    author='James Webb',
    author_email='james@ultra-horizon.com',
    license='Apache2',
    url='https://github.com/ultrahorizon/pyargon2',
    description="Simultaneously the simplest and most powerful Argon2 implemenation in Python",
    packages=find_packages(),
    keywords="argon2 hash password",
    classifiers=[
        'Development Status :: 4 - Beta',
        # 'Development Status :: 5 - Production/Stable',

        'Intended Audience :: Developers',
        'License :: OSI Approved :: Apache Software License',

        'Operating System :: MacOS',
        'Operating System :: POSIX',
        'Operating System :: Unix',

        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: Implementation :: CPython',
        'Programming Language :: Python :: Implementation :: PyPy',

        'Topic :: Security',
        'Topic :: Security :: Cryptography',
        'Topic :: Software Development :: Libraries',
    ],
    zip_safe=False,
    ext_package="pyargon2",

    # Compile C extensions
    setup_requires=["cffi>=1.0.0"],
    cffi_modules=["pyargon2/_compiler.py:ffi"],
    install_requires=["cffi>=1.0.0"]
)
