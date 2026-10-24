"""Exercises incompatible kernels independently of successful BPF compilation."""

import unittest

from userns_bpf_kernel import REQUIRED_CONFIG, check_kernel


CONFIG = "\n".join(f"CONFIG_{option}=y" for option in REQUIRED_CONFIG)
BTF = """[7] PTR '(anon)' type_id=99
[23] FUNC_PROTO '(anon)' ret_type_id=0 vlen=1
    'namespace' type_id=7
[61] FUNC 'retire_userns_sysctls' type_id=23 linkage=static
[99] STRUCT 'user_namespace' size=896 vlen=1
    'irrelevant_member' type_id=123 bits_offset=0
"""


class KernelContractTest(unittest.TestCase):
    def check(self, btf=BTF, config=CONFIG):
        check_kernel(config, btf.splitlines(keepends=True))

    def test_selected_typed_signature(self):
        self.check()
        self.check(BTF.replace("linkage=static", "linkage=global"))

    def test_trampoline_prerequisites_are_mandatory(self):
        for option in REQUIRED_CONFIG:
            with self.subTest(option=option), self.assertRaisesRegex(ValueError, option):
                self.check(config=CONFIG.replace(f"CONFIG_{option}=y", f"# CONFIG_{option} is not set"))

    def test_missing_or_ambiguous_function(self):
        with self.assertRaisesRegex(ValueError, "exactly one"):
            self.check(BTF.replace("retire_userns_sysctls", "unrelated"))
        with self.assertRaisesRegex(ValueError, "exactly one"):
            self.check(BTF + "[100] FUNC 'retire_userns_sysctls' type_id=23 linkage=static\n")

    def test_changed_function_signature(self):
        for before, after in (
            ("ret_type_id=0", "ret_type_id=7"),
            ("ret_type_id=0 vlen=1", "ret_type_id=0 vlen=2"),
            ("'namespace' type_id=7", "'namespace' type_id=99"),
            ("STRUCT 'user_namespace'", "STRUCT 'net'"),
            ("type_id=99", "type_id=7"),
            ("'namespace' type_id=7\n", ""),
        ):
            with self.subTest(after=after), self.assertRaises(ValueError):
                self.check(BTF.replace(before, after))

    def test_incomplete_type_graph(self):
        with self.assertRaisesRegex(ValueError, "incomplete"):
            self.check(BTF.replace("type_id=23", "type_id=200"))


if __name__ == "__main__":
    unittest.main()
