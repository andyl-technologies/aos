"""Rejects the observed OpenSSL archive-linking regression independently of features."""

import unittest
from copy import deepcopy
from unittest.mock import patch

from verify_cli_package import compare_installed, dynamic_symbols, openssl_imports, validate_openssl_flags


class OpenSslLinkageTests(unittest.TestCase):
    def test_versioned_dynamic_symbol_imports_and_exports(self):
        table = """
   Num:    Value          Size Type    Bind   Vis      Ndx Name
     1: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND SSL_connect@OPENSSL_3.0.0 (2)
     2: 0000000000001000    23 FUNC    GLOBAL DEFAULT   12 SSL_new@@OPENSSL_3.0.0
"""
        with patch("verify_cli_package.subprocess.check_output", return_value=table):
            self.assertEqual(dynamic_symbols("program", "readelf", undefined=True), {"SSL_connect"})
            self.assertEqual(dynamic_symbols("library", "readelf", undefined=False), {"SSL_new"})

    def test_openssl_import_regression_is_rejected(self):
        records = {"ordinary": {"out/bin/aos": {"kind": "elf", "contract": {
            "resolved_libraries": ["/nix/store/openssl/lib/libssl.so.4"],
        }}}}
        packages = {"ordinary": {"out": "/ordinary"}, "bazel": {"out": "/bazel"}}
        with patch("verify_cli_package.dynamic_symbols", side_effect=[{"SSL_connect"}, {"SSL_connect"}, set()]):
            with self.assertRaisesRegex(ValueError, "OpenSSL imports differ"):
                openssl_imports(packages, records, "readelf")

    def test_shared_libraries(self):
        for text in ("-lssl\n-lcrypto\n", "-ldylib=ssl\n-ldylib=crypto\n-lz\n"):
            with self.subTest(flags=text):
                self.assertTrue(validate_openssl_flags(text))

    def test_archive_linking_and_missing_or_conflicting_imports(self):
        for text in ("-lstatic=ssl\n-lstatic=crypto\n-lz\n-ldl\n",
                     "-lssl\n-lstatic=crypto\n", "-lcrypto\n", "",
                     "-lssl\n-lcrypto\n-lstatic=ssl\n"):
            with self.subTest(flags=text), self.assertRaisesRegex(ValueError, "shared library"):
                validate_openssl_flags(text)


class InstalledContractTests(unittest.TestCase):
    def setUp(self):
        directory_exists = patch("installed_package.Path.is_dir", return_value=True)
        directory_exists.start()
        self.addCleanup(directory_exists.stop)
        self.baseline = {"apm/bin/.apm-unwrapped": {
            "kind": "elf", "mode": 0o555, "contract": {
                "needed": ["libssl.so.4", "libcrypto.so.4"],
                "interpreter": ["/nix/store/loader"],
                "resolved_libraries": ["/nix/store/openssl/lib/libssl.so.4"],
                "rpath_directories": ["/nix/store/fixture/lib", "/deleted/unused-library-directory"],
            },
        }}
        self.candidate = deepcopy(self.baseline)
        self.candidate["apm/bin/.apm-unwrapped"]["contract"]["rpath_directories"] = ["/nix/store/fixture/lib"]

    def test_unused_search_directory_removal_is_reported(self):
        changes = compare_installed(self.baseline, self.candidate)

        self.assertEqual(changes, {"apm/bin/.apm-unwrapped": {
            "added": [], "removed": ["/deleted/unused-library-directory"],
        }})

    def test_loader_import_permission_and_search_path_changes_are_rejected(self):
        mutations = [
            ("needed", ["libcrypto.so.4"]),
            ("resolved_libraries", ["/nix/store/other-openssl/lib/libssl.so.4"]),
            ("interpreter", ["/nix/store/other-loader"]),
            ("rpath_directories", ["/nix/store/fixture/lib", "$ORIGIN/../../../_solib_x86_64/library"]),
        ]
        for field, value in mutations:
            candidate = deepcopy(self.candidate)
            candidate["apm/bin/.apm-unwrapped"]["contract"][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                compare_installed(self.baseline, candidate)

        self.candidate["apm/bin/.apm-unwrapped"]["mode"] = 0o777
        with self.assertRaises(ValueError):
            compare_installed(self.baseline, self.candidate)


if __name__ == "__main__":
    unittest.main()
