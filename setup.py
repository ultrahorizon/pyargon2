from setuptools import find_packages, setup

with open('README.md') as fd:
    readme = fd.read()

setup(
    name='pyargon2',
    version='1.0.0',
    author='James Webb',
    author_email='james@ultra-horizon.com',
    license='Apache2',
    url='https://github.com/ultrahorizon/pyargon2',
    description="Simultaneously the simplest and most powerful Argon2 implemenation in Python",
    packages=find_packages(),
    keywords="argon2 hash password",
    long_description=readme,
    long_description_content_type='text/markdown',
    classifiers=[
        # 'Development Status :: 4 - Beta',
        'Development Status :: 5 - Production/Stable',

        'Intended Audience :: Developers',
        'License :: OSI Approved :: Apache Software License',

        'Operating System :: MacOS',
        'Operating System :: Microsoft :: Windows',
        'Operating System :: POSIX',
        'Operating System :: Unix',

        'Programming Language :: Python :: 3',

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
