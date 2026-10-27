"""Keeps UEFI console controls from concealing boot failures in Nix logs."""

import unittest

from aos_test_driver import __main__ as driver


class SerialDiagnosticsTests(unittest.TestCase):
    def test_uefi_queries_leave_following_kernel_diagnostics_readable(self):
        raw = (
            b"\x1b[2J\x1b[001;001HUEFI boot\r\n"
            b"\x1bP+q6E616D65\x1b\\"
            b"[    3.7] nix-store: immutable store\r\n"
            b"\x1b]0;serial console\x07systemd: failed\r\n"
        )

        self.assertEqual(
            driver._plain_serial_log(raw),
            b"UEFI boot\n[    3.7] nix-store: immutable store\nsystemd: failed\n",
        )

    def test_plain_utf8_text_and_raw_input_are_preserved(self):
        raw = "guest diagnostic: café\n\tcontinued\n".encode()

        self.assertEqual(driver._plain_serial_log(raw), raw)


if __name__ == "__main__":
    unittest.main()
