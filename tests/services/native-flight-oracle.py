"""Checks the source-backed service/account oracle's independent observations."""

import ast
import contextlib
import hashlib
import io
import os
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

    def observe(self, operation, service_name="native-service-qualification", account_mount=False):
        request = {"operation": operation, "systemctl": "/store/systemctl",
                   "root": "/var/lib/aos/native-service-qualification", "service": service_name, "accountMount": account_mount}
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

    def test_blocking_oneshot_uses_real_execution_pid_and_own_marker(self):
        name = "native-service-deadline"
        self.write(f"/etc/systemd/system/{name}.service", "[Service]\nType=oneshot\n")
        self.write(f"/sys/fs/cgroup/system.slice/{name}.service/cgroup.procs", "41")
        self.write("/var/lib/aos/native-service-qualification/deadline.invocations", "invoked\n")
        original_manager = self.manager

        def manager(arguments, **kwargs):
            result = original_manager(arguments, **kwargs)
            if arguments[2] == name + ".service":
                result.stdout = result.stdout.replace("ActiveState=active", "ActiveState=activating").replace(
                    "MainPID=41", "MainPID=0\nExecMainPID=41")
            return result

        self.manager = manager
        observed = self.observe("realize", name)["selected"]
        self.assertFalse(observed["active"])
        self.assertEqual(observed["processCount"], 1)
        self.assertEqual(observed["command"], ["/store/coreutils/bin/sleep", "infinity"])
        self.assertEqual(observed["invocations"], 1)

    def test_blocking_stop_reports_both_live_processes_and_actual_stop_marker(self):
        name = "native-service-deadline-remove"
        self.write(f"/etc/systemd/system/{name}.service", "[Service]\nTimeoutStopSec=infinity\n")
        self.write(f"/sys/fs/cgroup/system.slice/{name}.service/cgroup.procs", "41\n43\n")
        self.write("/var/lib/aos/native-service-qualification/deadline-remove.invocations", "invoked\n")
        self.write("/var/lib/aos/native-service-qualification/deadline-stop.invocations", "invoked\n")
        original_manager = self.manager

        def manager(arguments, **kwargs):
            result = original_manager(arguments, **kwargs)
            if arguments[2] == name + ".service":
                result.stdout = result.stdout.replace("ActiveState=active", "ActiveState=deactivating")
            return result

        self.manager = manager
        observed = self.observe("realize", name)["selected"]
        self.assertFalse(observed["active"])
        self.assertEqual(observed["processCount"], 2)
        self.assertEqual(observed["invocations"], 1)
        self.assertEqual(observed["stopInvocations"], 1)

    def test_unit_bytes_and_extra_command_invocation_are_visible(self):
        before = self.observe("realize")
        self.write("/var/lib/aos/native-service-qualification/selected.invocations", "invoked\ninvoked\n")
        self.write("/etc/systemd/system/native-service-qualification.service", "external mutation\n")
        after = self.observe("realize")
        self.assertEqual(after["selected"]["invocations"], 2)
        self.assertEqual(after["selected"]["unitDigest"], hashlib.sha256(b"external mutation\n").hexdigest())
        self.assertEqual(before["foreign"], after["foreign"])

    def test_readonly_precondition_binds_real_mount_record_and_complete_account_bytes(self):
        self.write("/proc/self/mountinfo", "123 55 0:42 /etc/group /etc/group ro,nosuid - overlay overlay rw\n")
        reading = self.observe("membership", account_mount=True)
        precondition = reading["selected"]["precondition"]
        self.assertEqual(precondition["kind"], "read-only-account-database")
        self.assertEqual(precondition["options"], ["nosuid", "ro"])
        self.assertEqual(precondition["superOptions"], ["rw"])
        self.assertEqual(precondition["mountId"], 123)
        self.assertEqual(precondition["contentSha256"], "sha256:" + hashlib.sha256((self.root / "etc/group").read_bytes()).hexdigest())
        self.write("/proc/self/mountinfo", "123 55 0:42 /etc/group /etc/group rw - overlay overlay rw\n")
        with self.assertRaisesRegex(RuntimeError, "not protected by its read-only mount"):
            self.observe("membership", account_mount=True)

    def test_shared_membership_group_numeric_mutation_is_foreign_drift(self):
        before = self.observe("membership")
        self.write("/etc/group", "aos-nq-selected:x:61501:\naos-nq-members:x:61509:aos-nq-member,aos-nq-foreign\naos-nq-foreign:x:61503:\n")
        after = self.observe("membership")
        self.assertEqual(before["selected"], after["selected"])
        self.assertNotEqual(before["foreign"], after["foreign"])
        self.assertEqual(after["foreign"]["membershipGroupIdentity"], ["aos-nq-members", "x", "61509"])

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


class NativeMarkerOracleTests(unittest.TestCase):
    def test_protected_physical_claim_and_foreign_inode_are_observed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            marker_root = root / "var/lib/aos/native-dependency-barrier"
            marker_root.mkdir(parents=True, mode=0o700)
            for name in ("group-parent", "foreign-marker"):
                marker = marker_root / name
                marker.write_text(json.dumps({"effect": "actual-" + name, "revision": "resolved-revision"}))
                marker.chmod(0o600)
            output = io.StringIO()
            original_fstat = os.fstat
            def metadata(descriptor):
                value = list(original_fstat(descriptor))
                value[4] = 0
                return os.stat_result(value)
            class RootMetadata:
                st_mode = 0o40700
                st_uid = 0
            with patch("pathlib.Path", side_effect=lambda value: root / str(value).lstrip("/")), \
                 patch.object(Path, "lstat", return_value=RootMetadata()), \
                 patch("os.fstat", side_effect=metadata), \
                 patch("sys.argv", ["marker-oracle", "group-parent"]), \
                 contextlib.redirect_stdout(output):
                exec(compile(domain["MARKER_ORACLE_SOURCE"], "physical-marker-oracle", "exec"), {})
            reading = json.loads(output.getvalue())
            self.assertEqual(reading["selected"]["owners"], ["actual-group-parent"])
            self.assertEqual(reading["foreign"]["owners"], ["actual-foreign-marker"])
            self.assertEqual(reading["foreign"]["inode"], (marker_root / "foreign-marker").stat().st_ino)


class NativeGuestProgramTests(unittest.TestCase):
    def test_account_lock_and_injection_programs_compile_after_substitution(self):
        templates = [node.value for node in ast.walk(source) if isinstance(node, ast.Constant)
                     and isinstance(node.value, str) and "%r" in node.value
                     and ("fcntl" in node.value or "metadata = os.stat" in node.value)]
        self.assertEqual(len(templates), 3)
        for template in templates:
            arguments = ("group", ["aos-nq-selected", "x", "61509", ""]) if "row = %r" in template else ("/tmp/lock-ready",)
            compile(template % arguments, "native-guest-lock-program", "exec")

    @unittest.skipUnless(Path("/proc/locks").is_file(), "requires Linux POSIX lock observations")
    def test_kernel_lock_proof_matches_actual_process_and_inode(self):
        import fcntl
        template = next(node.value for node in ast.walk(source) if isinstance(node, ast.Constant)
                        and isinstance(node.value, str) and "metadata = os.stat" in node.value)
        with tempfile.TemporaryDirectory() as directory:
            lock_path = Path(directory) / "account.lock"
            marker = Path(directory) / "ready"
            marker.write_text(str(os.getpid()))
            descriptor = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o600)
            try:
                fcntl.lockf(descriptor, fcntl.LOCK_EX)
                program = (template % str(marker)).replace("'/etc/.pwd.lock'", repr(str(lock_path)))
                exec(compile(program, "actual-kernel-lock-proof", "exec"), {})
                fcntl.lockf(descriptor, fcntl.LOCK_UN)
                with self.assertRaises(AssertionError):
                    exec(compile(program, "released-kernel-lock-proof", "exec"), {})
            finally:
                os.close(descriptor)


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

    def test_deadline_selects_distinct_authored_blocking_effect(self):
        deadline = dict(self.cell, scenario={"id": "expire-invocation-deadline"})
        name = "native-service-deadline"
        node = dict(self.node, identity=self.node["identity"][:-1] + [name])
        graph = {"nodes": {"deadline-effect": node, "ordinary-effect": self.node}}
        self.assertTrue(domain["supports"](deadline, self.adapter, graph))
        self.assertEqual(domain["selected_effect"](graph, deadline, self.adapter), "deadline-effect")
        removal = dict(deadline, action="remove")
        self.assertFalse(domain["supports"](removal, self.adapter, graph))
        self.assertEqual(domain["resource_name"](removal), "native-service-deadline-remove")

    def test_cancellation_keeps_original_controlled_descriptor(self):
        cancellation = dict(self.cell, scenario={"id": "cancel-pending-invocation"})
        self.assertTrue(domain["supports"](cancellation, self.adapter, self.graph))
        self.assertEqual(domain["selected_effect"](self.graph, cancellation, self.adapter), "checked-effect")

    def test_account_rejection_routes_keep_owned_lease_preconditions(self):
        cell = dict(self.cell, operation={"ability": "identity", "name": "group"}, action="remove",
                    scenario={"id": "fail-manager-after-dispatch-attempt"})
        node = dict(self.node, identity=self.node["identity"][:-3] + ["identity", "group", "native-service-qualification"])
        graph = {"nodes": {"group-effect": node}}
        self.assertTrue(domain["supports"](cell, self.adapter, graph))
        replay = dict(cell, scenario={"id": "reject-uncertain-recovery"})
        self.assertTrue(domain["supports"](replay, self.adapter, graph))
        membership = dict(cell, operation={"ability": "identity", "name": "membership"})
        membership_node = dict(node, identity=node["identity"][:-2] + ["membership", "native-service-qualification"])
        self.assertTrue(domain["supports"](membership, self.adapter, {"nodes": {"membership-effect": membership_node}}))
        foreign_denial = dict(membership, scenario={"id": "reject-foreign-resource-mutation"})
        self.assertTrue(domain["supports"](foreign_denial, self.adapter, {"nodes": {"membership-effect": membership_node}}))

    def test_unsupported_scenarios_and_duplicate_effects_fail_closed(self):
        unsupported = dict(self.cell, scenario={"id": "retain-persistent-orphan"})
        self.assertFalse(domain["supports"](unsupported, self.adapter, self.graph))
        duplicate = {"nodes": dict(self.graph["nodes"], other=self.node)}
        with self.assertRaisesRegex(RuntimeError, "no unique admitted effect"):
            domain["selected_effect"](duplicate, self.cell, self.adapter)


if __name__ == "__main__":
    unittest.main()
