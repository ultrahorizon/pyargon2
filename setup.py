#!/usr/bin/env python
# -*- encoding: utf-8 -*-

from __future__ import print_function

import os
import platform
import sys

from distutils.command.build import build
from distutils.command.build_clib import build_clib
from distutils.errors import DistutilsSetupError
from setuptools import setup, find_packages
from setuptools.command.install import install

CFFI_MODULES = ["pyargon2/compilation/argon2_pypi.py:ffi"]
lib_base = 'extern/argon2/src'
include_dirs = ['extern/argon2/include']
optimized = platform.machine() in ("i686", "x86", "x86_64", "AMD64")

LIBRARIES = [
    ("argon2", {
        "include_dirs": include_dirs,
        "sources": [
            os.path.join(lib_base, path) for path in [
                "argon2.c",
                "core.c",
                "blake2/blake2b.c",
                "thread.c",
                "encoding.c",
                "opt.c" if optimized else "ref.c"
            ]
        ],
    }),
]

SETUP_REQUIRES = ["cffi"]


def keywords_with_side_effects(argv):
    """
    Get a dictionary with setup keywords that (can) have side effects.

    :param argv: A list of strings with command line arguments.

    :returns: A dictionary with keyword arguments for the ``setup()`` function.
        This setup.py script uses the setuptools 'setup_requires' feature
        because this is required by the cffi package to compile extension
        modules. The purpose of ``keywords_with_side_effects()`` is to avoid
        triggering the cffi build process as a result of setup.py invocations
        that don't need the cffi module to be built (setup.py serves the dual
        purpose of exposing package metadata).

    Stolen from pyca/cryptography.
    """
    no_setup_requires_arguments = (
        '-h', '--help',
        '-n', '--dry-run',
        '-q', '--quiet',
        '-v', '--verbose',
        '-V', '--version',
        '--author',
        '--author-email',
        '--classifiers',
        '--contact',
        '--contact-email',
        '--description',
        '--egg-base',
        '--fullname',
        '--help-commands',
        '--keywords',
        '--licence',
        '--license',
        '--long-description',
        '--maintainer',
        '--maintainer-email',
        '--name',
        '--no-user-cfg',
        '--obsoletes',
        '--platforms',
        '--provides',
        '--requires',
        '--url',
        'clean',
        'egg_info',
        'register',
        'sdist',
        'upload',
    )

    def is_short_option(argument):
        """Check whether a command line argument is a short option."""
        return len(argument) >= 2 and argument[0] == '-' and argument[1] != '-'

    def expand_short_options(argument):
        """Expand combined short options into canonical short options."""
        return ('-' + char for char in argument[1:])

    def argument_without_setup_requirements(argv, i):
        """Check whether a command line argument needs setup requirements."""
        if argv[i] in no_setup_requires_arguments:
            # Simple case: An argument which is either an option or a command
            # which doesn't need setup requirements.
            return True
        elif (is_short_option(argv[i]) and
              all(option in no_setup_requires_arguments
                  for option in expand_short_options(argv[i]))):
            # Not so simple case: Combined short options none of which need
            # setup requirements.
            return True
        elif argv[i - 1:i] == ['--egg-base']:
            # Tricky case: --egg-info takes an argument which should not make
            # us use setup_requires (defeating the purpose of this code).
            return True
        else:
            return False

    if all(argument_without_setup_requirements(argv, i)
           for i in range(1, len(argv))):
        return {
            "cmdclass": {
                "build": DummyBuild,
                "install": DummyInstall,
            }
        }
    else:
        return {
            "setup_requires": SETUP_REQUIRES,
            "cffi_modules": CFFI_MODULES,
            "libraries": LIBRARIES,
            "cmdclass": {
                "build_clib": BuildCLibWithCompilerFlags,
            },
        }


setup_requires_error = (
    "Requested setup command that needs 'setup_requires' while command line "
    "arguments implied a side effect free command or option."
)


class DummyBuild(build):
    """
    This class makes it very obvious when ``keywords_with_side_effects()`` has
    incorrectly interpreted the command line arguments to ``setup.py build`` as
    one of the 'side effect free' commands or options.
    """

    def run(self):
        raise RuntimeError(setup_requires_error)


class DummyInstall(install):
    """
    This class makes it very obvious when ``keywords_with_side_effects()`` has
    incorrectly interpreted the command line arguments to ``setup.py install``
    as one of the 'side effect free' commands or options.
    """

    def run(self):
        raise RuntimeError(setup_requires_error)


class BuildCLibWithCompilerFlags(build_clib):
    """
    We need to pass ``-msse2`` for the optimized build.
    """

    def build_libraries(self, libraries):
        """
        Mostly copy pasta from ``distutils.command.build_clib``.
        """
        for (lib_name, build_info) in libraries:
            sources = build_info.get('sources')
            if sources is None or not isinstance(sources, (list, tuple)):
                raise DistutilsSetupError(
                    "in 'libraries' option (library '%s'), "
                    "'sources' must be present and must be "
                    "a list of source filenames" % lib_name)
            sources = list(sources)

            print("building '%s' library" % (lib_name,))

            # First, compile the source code to object files in the library
            # directory.  (This should probably change to putting object
            # files in a temporary build directory.)
            macros = build_info.get('macros')
            include_dirs = build_info.get('include_dirs')
            objects = self.compiler.compile(
                sources,
                extra_preargs=["-msse2"] if optimized else [],
                output_dir=self.build_temp,
                macros=macros,
                include_dirs=include_dirs,
                debug=self.debug
            )

            # Now "link" the object files together into a static library.
            # (On Unix at least, this isn't really linking -- it just
            # builds an archive.  Whatever.)
            self.compiler.create_static_lib(objects, lib_name,
                                            output_dir=self.build_clib,
                                            debug=self.debug)


with open(os.path.join(os.path.dirname(__file__), 'README.md')) as fh:
    long_description = fh.read()

setup(
    name='pyargon2',
    version='0.1.8',
    author='James Webb',
    author_email='james@ultra-horizon.com',
    license='Apache2',
    url='https://github.com/ultrahorizon/pyargon2',
    description="Simultaneously the simplest and most powerful Argon2 implemenation in Python",
    packages=find_packages(),
    install_requires=['cffi>=1.0.0'],
    keywords="argon2 hash password",
    long_description=long_description,
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

    # CFFI
    zip_safe=False,
    ext_package="pyargon2",
    **keywords_with_side_effects(sys.argv)
)
