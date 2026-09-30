"""Checks the source-backed service/account oracle's independent observations."""

import ast
import contextlib
import hashlib
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch


source = ast.parse(Path(sys.argv.pop(1)).read_text())
domain = {}
exec(compile(source, "native-reference-service-flights", "exec"), domain)
oracle = next(ast.literal_eval(node.value) for node in source.body
              if isinstance(node, ast.Assign)
              and any(isinstance(target, ast.Name) and target.id == "ORACLE_SOURCE" for target in node.targets))


class NativeServiceOracleTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.write("/etc/group", "aos-nq-selected:x:61501:\naos-nq-members:x:61502:aos-nq-member,aos-nq-foreign\naos-nq-foreign:x:61503:\n")
        self.write("/etc/passwd", "aos-nq-selected:x:61501:61503:baseline:/var/empty:/store/nologin\naos-nq-foreign:x:61503:61503:foreign:/var/empty:/store/nologin\n")
        for name, pid in (("native-service-qualification", 41), ("native-service-foreign", 42)):
            self.write(f"/etc/systemd/system/{name}.service", f"[Service]\nDescription={name}\n")
            self.write(f"/proc/{pid}/cmdline", b"/store/coreutils/bin/sleep\0infinity\0")
            self.write(f"/sys/fs/cgroup/system.slice/{name}.service/cgroup.procs", str(pid))
        for marker in ("selected", "foreign"):
            self.write(f"/var/lib/aos/native-service-qualification/{marker}.invocations", "invoked\n")

    def write(self, path, value):
        destination = self.root / path.lstrip("/")
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(value if isinstance(value, bytes) else value.encode())

    def manager(self, arguments, **kwargs):
        unit = arguments[2]
        pid = 42 if unit.endswith("foreign.service") else 41
        return subprocess.CompletedProcess(arguments, 0,
            f"Id={unit}\nLoadState=loaded\nActiveState=active\nMainPID={pid}\n"
            f"InvocationID=actual-{pid}\nFragmentPath=/etc/systemd/system/{unit}\n"
            f"ControlGroup=/system.slice/{unit}\n", "")

    def observe(self, operation):
        request = {"operation": operation, "systemctl": "/store/systemctl",
                   "root": "/var/lib/aos/native-service-qualification"}
        output = io.StringIO()
        with patch("pathlib.Path", side_effect=lambda value: self.root / str(value).lstrip("/")), \
             patch("subprocess.run", side_effect=self.manager), \
             patch("sys.argv", ["oracle", json.dumps(request)]), \
             contextlib.redirect_stdout(output):
            exec(compile(oracle, "native-service-oracle", "exec"), {})
        return json.loads(output.getvalue())

    def test_reads_real_process_identity_and_process_written_marker(self):
        selected = self.observe("realize")["selected"]
        self.assertEqual(selected["command"], ["/store/coreutils/bin/sleep", "infinity"])
        self.assertEqual(selected["processCount"], 1)
        self.assertEqual(selected["invocations"], 1)
        self.assertEqual(selected["owners"], ["systemd:native-service-qualification.service"])

    def test_unit_bytes_and_extra_command_invocation_are_visible(self):
        before = self.observe("realize")
        self.write("/var/lib/aos/native-service-qualification/selected.invocations", "invoked\ninvoked\n")
        self.write("/etc/systemd/system/native-service-qualification.service", "external mutation\n")
        after = self.observe("realize")
        self.assertEqual(after["selected"]["invocations"], 2)
        self.assertEqual(after["selected"]["unitDigest"], hashlib.sha256(b"external mutation\n").hexdigest())
        self.assertEqual(before["foreign"], after["foreign"])

    def test_rejects_foreign_symlink_in_place_of_owned_unit(self):
        unit = self.root / "etc/systemd/system/native-service-qualification.service"
        unit.unlink()
        unit.symlink_to("native-service-foreign.service")
        with self.assertRaisesRegex(RuntimeError, "unexpected symbolic link"):
            self.observe("realize")

    def test_rejects_main_process_missing_from_cgroup(self):
        self.write("/sys/fs/cgroup/system.slice/native-service-qualification.service/cgroup.procs", "999")
        with self.assertRaisesRegex(RuntimeError, "absent from its real cgroup"):
            self.observe("realize")

    def test_principal_row_is_read_independently(self):
        observed = self.observe("principal")["selected"]
        self.assertEqual(observed["row"], ["aos-nq-selected", "x", "61501", "61503", "baseline", "/var/empty", "/store/nologin"])
        self.assertEqual(observed["owners"], ["principal:aos-nq-selected"])

    def test_removed_membership_preserves_independent_foreign_membership(self):
        before = self.observe("membership")
        self.write("/etc/group", "aos-nq-selected:x:61501:\naos-nq-members:x:61502:aos-nq-foreign\naos-nq-foreign:x:61503:\n")
        after = self.observe("membership")
        self.assertEqual(after["selected"], {"owners": [], "granted": False, "members": ["aos-nq-foreign"]})
        self.assertEqual(before["foreign"], after["foreign"])

    def test_duplicate_account_rows_and_lost_foreign_members_fail_closed(self):
        self.write("/etc/passwd", "aos-nq-selected:x:1:1::/:x\naos-nq-selected:x:2:2::/:x\n")
        with self.assertRaisesRegex(RuntimeError, "duplicate account"):
            self.observe("principal")
        self.write("/etc/group", "aos-nq-members:x:61502:aos-nq-member\n")
        with self.assertRaisesRegex(RuntimeError, "foreign membership disappeared"):
            self.observe("membership")


class NativeServiceSelectionTests(unittest.TestCase):
    def setUp(self):
        self.cell = {"operation": {"ability": "serviceManagement", "name": "realize"},
                     "scope": ["profile", "system"], "action": "apply",
                     "scenario": {"id": "lose-external-result"}}
        self.adapter = {"handler": {"kind": "process", "program": "/store/handler"}}
        self.node = {"identity": ["profile", "system", "service-management", "serviceManagement", "realize", "native-service-qualification"],
                     "handler": self.adapter["handler"]}
        self.graph = {"nodes": {"checked-effect": self.node}}

    def test_accepts_only_actual_controlled_scope_and_handler(self):
        self.assertTrue(domain["supports"](self.cell, self.adapter, self.graph))
        self.assertEqual(domain["selected_effect"](self.graph, self.cell, self.adapter), "checked-effect")
        wrong_scope = dict(self.cell, scope=["initrd"])
        self.assertFalse(domain["supports"](wrong_scope, self.adapter, self.graph))
        with self.assertRaisesRegex(RuntimeError, "no unique admitted effect"):
            domain["selected_effect"](self.graph, wrong_scope, self.adapter)
        self.assertFalse(domain["supports"](self.cell, {"handler": {"kind": "process", "program": "/store/other"}}, self.graph))

    def test_unsupported_scenarios_and_duplicate_effects_fail_closed(self):
        unsupported = dict(self.cell, scenario={"id": "reject-indeterminate-replay"})
        self.assertFalse(domain["supports"](unsupported, self.adapter, self.graph))
        duplicate = {"nodes": dict(self.graph["nodes"], other=self.node)}
        with self.assertRaisesRegex(RuntimeError, "no unique admitted effect"):
            domain["selected_effect"](duplicate, self.cell, self.adapter)


if __name__ == "__main__":
    unittest.main()
