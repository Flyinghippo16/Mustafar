#!/usr/bin/python3.3
import errno
import os
import shutil
import sys
import tempfile
import unittest

##import modulefinder
import py2exe.mf310 as modulefinder

TEST_DIR = 'synthetic'
TEST_PATH = [TEST_DIR]#, os.path.dirname(tempfile.__file__)]

print("TEST_PATH is", TEST_PATH)

# Each test description is a list of 5 items:
#
# 1. a module name that will be imported by modulefinder
# 2. a list of module names that modulefinder is required to find
# 3. a list of module names that modulefinder should complain
#    about because they are not found
# 4. a list of module names that modulefinder should complain
#    about because they MAY be not found
# 5. a string specifying packages to create; the format is obvious imo.
#
# Each package will be created in TEST_DIR, and TEST_DIR will be
# removed after the tests again.
# Modulefinder searches in a path that contains TEST_DIR, plus
# the standard Lib directory.

maybe_test = [
    "a.module",
    ["a", "a.module", "sys",
     "b"],
    ["c"], ["b.something"],
    """\
a/__init__.py
a/module.py
                                from b import something
                                from c import something
b/__init__.py
                                from sys import *
"""]

maybe_test_new = [
    "a.module",
    ["a", "a.module", "sys",
     "b", "__future__"],
    ["c"], ["b.something"],
    """\
a/__init__.py
a/module.py
                                from b import something
                                from c import something
b/__init__.py
                                from __future__ import absolute_import
                                from sys import *
"""]

package_test = [
    "a.module",
    ["a", "a.b", "a.c", "a.module", "mymodule", "sys"],
    ["blahblah", "c"], [],
    """\
mymodule.py
a/__init__.py
                                import blahblah
                                from a import b
                                import c
a/module.py
                                import sys
                                from a import b as x
                                from a.c import sillyname
a/b.py
a/c.py
                                from a.module import x
                                import mymodule as sillyname
                                from sys import version_info
"""]

namespace_package_test = [
    "a.module",
    ["a", "a.b", "a.c", "a.module", "sys", "q", "q.pkg"],
    ["blahblah", "z"], [],
    """\
a/__init__.py
                                from a import b
a/module.py
                                import sys
                                from a import b as x
                                from a.c import sillyname
                                from q import pkg
                                import blahblah
a/b.py
a/c.py
                                from a.module import x
                                from sys import version_info
q/pkg.py
                                import z
"""]

absolute_import_test = [
    "a.module",
    ["a", "a.module",
     "b", "b.x", "b.y", "b.z",
     "__future__", "sys", "gc"],
    ["blahblah", "z"], [],
    """\
mymodule.py
a/__init__.py
a/module.py
                                from __future__ import absolute_import
                                import sys # sys
                                import blahblah # fails
                                import z # fails
                                import gc # gc
                                import b.x # b.x
                                from b import y # b.y
                                from b.z import * # b.z.*
a/gc.py
a/sys.py
                                import mymodule
b/__init__.py
                                from . import z
b/unused.py
b/x.py
b/y.py
b/z.py
"""]

relative_import_test = [
    "a.module",
    ["__future__",
     "a", "a.module",
     "a.b", "a.b.y", "a.b.z",
     "a.b.c", "a.b.c.moduleC",
     "a.b.c.d", "a.b.c.e",
     "a.b.x",
     "gc"],
    [], [],
    """\
mymodule.py
a/__init__.py
                                from .b import y, z # a.b.y, a.b.z
a/module.py
                                from __future__ import absolute_import # __future__
                                import gc # gc
a/gc.py
a/sys.py
a/b/__init__.py
                                from ..b import x # a.b.x
                                #from a.b.c import moduleC
                                from .c import moduleC # a.b.moduleC
a/b/x.py
a/b/y.py
a/b/z.py
a/b/g.py
a/b/c/__init__.py
                                from ..c import e # a.b.c.e
a/b/c/moduleC.py
                                from ..c import d # a.b.c.d
a/b/c/d.py
a/b/c/e.py
a/b/c/x.py
"""]

relative_import_test_2 = [
    "a.module",
    ["a", "a.module",
     "a.sys",
     "a.b", "a.b.y", "a.b.z",
     "a.b.c", "a.b.c.d",
     "a.b.c.e",
     "a.b.c.moduleC",
     "a.b.c.f",
     "a.b.x",
     "a.another"],
    [], [],
    """\
mymodule.py
a/__init__.py
                                from . import sys # a.sys
a/another.py
a/module.py
                                from .b import y, z # a.b.y, a.b.z
a/gc.py
a/sys.py
a/b/__init__.py
                                from .c import moduleC # a.b.c.moduleC
                                from .c import d # a.b.c.d
a/b/x.py
a/b/y.py
a/b/z.py
a/b/c/__init__.py
                                from . import e # a.b.c.e
a/b/c/moduleC.py
                                #
                                from . import f   # a.b.c.f
                                from .. import x  # a.b.x
                                from ... import another # a.another
a/b/c/d.py
a/b/c/e.py
a/b/c/f.py
"""]

relative_import_test_3 = [
    "a.module",
    ["a", "a.module"],
    ["a.bar"],
    [],
    """\
a/__init__.py
                                def foo(): pass
a/module.py
                                from . import foo
                                from . import bar
"""]


def open_file(path):
    dirname = os.path.dirname(path)
    try:
        os.makedirs(dirname)
    except OSError as e:
        if e.errno != errno.EEXIST:
            raise
    return open(path, "w")


def create_package(source):
    ofi = None
    try:
        for line in source.splitlines():
            if line.startswith(" ") or line.startswith("\t"):
                ofi.write(line.strip() + "\n")
            else:
                if ofi:
                    ofi.close()
                ofi = open_file(os.path.join(TEST_DIR, line.strip()))
    finally:
        if ofi:
            ofi.close()


class ModuleFinderTest(unittest.TestCase):
    def _do_test(self, info, report=False):
        import_this, modules, missing, maybe_missing, source = info
        create_package(source)
        sys_path = sys.path[:]
        sys.path.insert(0, TEST_DIR)
        try:
            mf = modulefinder.ModuleFinder()#path=TEST_PATH)
            mf.import_hook(import_this)
            if report:
                mf.report()
##                # This wouldn't work in general when executed several times:
##                opath = sys.path[:]
##                sys.path = TEST_PATH
##                try:
##                    __import__(import_this)
##                except:
##                    import traceback; traceback.print_exc()
##                sys.path = opath
##                return
            modules = sorted(set(modules))
            found = sorted(mf.modules)
            # check if we found what we expected, not more, not less
            self.assertEqual(found, modules)

            # check for missing and maybe missing modules
            bad, maybe = mf.any_missing_maybe()
            bad = sorted(bad)
            maybe = sorted(maybe)
            self.assertEqual(bad, missing)
            self.assertEqual(maybe, maybe_missing)
        finally:
            sys.path = sys_path
            shutil.rmtree(TEST_DIR)

    #@unittest.skip("test_package")
    def test_package(self):
        self._do_test(package_test)

    #@unittest.skip("test_namespace_package")
    def test_namespace_package(self):
        self._do_test(namespace_package_test)

    #@unittest.skip("test_maybe")
    def test_maybe(self):
        self._do_test(maybe_test)

    #@unittest.skip("test_maybe_new")
    def test_maybe_new(self):
        self._do_test(maybe_test_new)

    #@unittest.skip("test_absolute_imports")
    def test_absolute_imports(self):
        self._do_test(absolute_import_test)

    #@unittest.skip("test_relative_imports")
    def test_relative_imports(self):
        self._do_test(relative_import_test)

    #@unittest.skip("test_relative_imports_2")
    def test_relative_imports_2(self):
        self._do_test(relative_import_test_2)

    #@unittest.skip("test_relative_imports_3")
    def test_relative_imports_3(self):
        self._do_test(relative_import_test_3)


## def test_main():
##     support.run_unittest(ModuleFinderTest)

if __name__ == "__main__":
    unittest.main()
