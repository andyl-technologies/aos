"""Exercises native service reconciliation without changing host resources."""

import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import tomllib
import unittest
from unittest.mock import patch


handler_path = Path(sys.argv.pop(1)) if len(sys.argv) > 1 else Path(__file__).parents[2] / "pkgs/system/_systemd-abilities/service-handler.py"
spec = importlib.util.spec_from_file_location("service_handler", handler_path)
handler_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(handler_module)


def service():
    return {
        "service": "example", "enabled": True, "auto_start": True,
        "activation_owner": "ability",
        "lifecycle": {
            "description": "Example service", "execution_model": "foreground",
            "environment_files": [], "condition": [], "pre_start": [],
            "start": [{"executable": {"path": "/nix/store/example/bin/example", "arguments": ["a b", "$USER", "%i"]}, "ignore_failure": False}],
            "post_start": [], "stop": [], "post_stop": [],
            "restart": "on-failure", "restart_delay_millis": 1000,
            "configuration_change_action": "reload", "remain_after_exit": False,
            "start_timeout_millis": 90000, "stop_timeout_millis": 90000,
        },
    }


def invocation(ability, operation, value, revision="first", previous=None):
    return {"id": "example-effect", "effect": {"identity": ["test", ability, operation, "main"]}, "input": value, "revision": revision, "previous": previous}


class NativeHandlerTests(unittest.TestCase):
    def test_command_arguments_remain_literal(self):
        rendered = handler_module.realize_service(service())["units"]["example.service"]
        self.assertIn('"a b" "$$USER" "%%i"', rendered)
        self.assertIn("Restart=on-failure", rendered)

    def test_temporary_parent_mask_preserves_explicit_child_bind(self):
        value = service()
        value["isolation"] = {
            "privilege": "unprivileged", "network": "host", "temporary_directory": "shared",
            "filesystem": "read-only-system", "home_access": "inaccessible",
            "process_visibility": "host", "termination_scope": "all-processes",
            "permit_core_dumps": False, "devices": [],
            "host_paths": [{"source": "/var/lib/coordinator/fitness", "mode": "read-write"}],
            "temporary_filesystems": [{"path": "/var/lib/coordinator", "read_only": True}],
        }
        rendered = handler_module.realize_service(value)["units"]["example.service"]
        self.assertIn('TemporaryFileSystem="/var/lib/coordinator:ro"', rendered)
        self.assertIn('BindPaths="/var/lib/coordinator/fitness"', rendered)

    def test_daemon_scheduling_and_socket_directory_are_rendered(self):
        value = service()
        value["resources"] = {"resource_group": "aos-pkg-example-builds"}
        value["scheduling"] = {"cpu_policy": "batch", "nice": 0, "io_class": "best-effort", "io_priority": 5}
        value["socket_activation"] = {"sockets": [{
            "name": "daemon", "enabled": True, "endpoints": [],
            "mode": "0666", "directory_mode": "0755", "prerequisites": ["policy"], "remove_on_stop": True,
        }]}
        units = handler_module.realize_service(value)["units"]
        self.assertIn("Slice=aos-pkg-example-builds.slice", units["example.service"])
        self.assertIn("CPUSchedulingPolicy=batch", units["example.service"])
        socket = next(text for name, text in units.items() if name.endswith(".socket"))
        self.assertIn("DirectoryMode=0755", socket)
        self.assertIn("Requires=policy.service", socket)

    def test_resource_group_cannot_escape_owning_package(self):
        with tempfile.TemporaryDirectory() as root:
            value = service()
            value["resources"] = {"resource_group": "aos-pkg-foreign-builds"}
            instance = handler_module.Handler(invocation("serviceManagement", "realize", value), "unused", root, Path(root) / "state")
            with self.assertRaisesRegex(ValueError, "owning package"):
                instance.service("apply")

    def test_removal_guard_refusal_preserves_service_and_receipt(self):
        with tempfile.TemporaryDirectory() as root:
            value = service()
            value["lifecycle"]["removal_guard"] = [{
                "executable": {"path": "/nix/store/control/bin/control", "arguments": ["drained"]},
                "ignore_failure": False,
            }]
            instance = handler_module.Handler(invocation("serviceManagement", "realize", value), "unused", root, Path(root) / "state")
            calls = []
            instance.manager = lambda *args, **kwargs: (calls.append(args) or subprocess.CompletedProcess(args, 0, "", ""))
            with patch.object(handler_module.subprocess, "run") as guard:
                instance.service("apply")
                guard.assert_not_called()
                before = dict(instance.receipt)
                calls.clear()
                guard.return_value = subprocess.CompletedProcess([], 1, "", "workers remain")
                with self.assertRaisesRegex(ValueError, "workers remain"):
                    instance.service("remove")
                self.assertEqual(instance.receipt, before)
                self.assertTrue((Path(root) / "example.service").exists())
                self.assertEqual(calls, [])

    def test_disabling_service_stops_listener_without_removal_guard(self):
        with tempfile.TemporaryDirectory() as root:
            value = service()
            value["lifecycle"]["removal_guard"] = [{
                "executable": {"path": "/nix/store/control/bin/control", "arguments": ["drained"]},
                "ignore_failure": False,
            }]
            initial = handler_module.Handler(invocation("serviceManagement", "realize", value), "unused", root, Path(root) / "state")
            initial.manager = lambda *args, **kwargs: subprocess.CompletedProcess(args, 0, "", "")
            initial.service("apply")
            disabled = dict(value, enabled=False, auto_start=False)
            updated = handler_module.Handler(invocation("serviceManagement", "realize", disabled, "disabled", {}), "unused", root, Path(root) / "state")
            calls = []
            updated.manager = lambda *args, **kwargs: (calls.append(args) or subprocess.CompletedProcess(args, 0, "", ""))
            with patch.object(handler_module.subprocess, "run") as guard:
                updated.service("apply")
                guard.assert_not_called()
            self.assertTrue(any(call[0] == "stop" and "example.service" in call for call in calls))
            self.assertTrue((Path(root) / "example.service").exists())

    def test_structured_toml_roundtrips_nested_keys_and_arrays(self):
        value = {"server": {"name": "a b", "enabled": True, "ports": [443, 8443]}, "plugins.io.example": {"path": "/run/example", "registries": [{"host": "registry.example", "tls": True}]}}
        encoded = handler_module.serialize_toml(value)
        self.assertEqual(tomllib.loads(encoded), value)

    def test_configuration_update_observe_remove_and_external_edit_rejection(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "etc/example.conf"
            state = Path(root) / "state"
            value = {"path": str(path), "content": "first", "mode": "0600"}
            initial = handler_module.Handler(invocation("configuration", "file", value), "unused", root, state)
            first = initial.file("apply")
            self.assertEqual(path.read_text(), "first")
            self.assertEqual(initial.file("observe")["status"], "current")
            value = dict(value, content="second")
            updated = handler_module.Handler(invocation("configuration", "file", value, "second", {}), "unused", root, state)
            self.assertEqual(updated.file("observe")["status"], "retry-safe")
            second = updated.file("apply")
            self.assertNotEqual(first["resource"], second["resource"])
            path.write_text("external")
            self.assertEqual(updated.file("observe")["status"], "indeterminate")
            with self.assertRaises(ValueError):
                updated.file("remove")
            path.write_text("second")
            updated.file("remove")
            self.assertFalse(path.exists())

    def test_service_update_reload_and_owned_removal(self):
        with tempfile.TemporaryDirectory() as root:
            units = Path(root) / "units"
            state = Path(root) / "state"
            value = service()
            first = handler_module.Handler(invocation("serviceManagement", "realize", value), "unused", units, state)
            commands = []
            def manager(*args, **kwargs):
                commands.append(args)
                return subprocess.CompletedProcess(args, 0, "active\n", "")
            first.manager = manager
            first.service("apply")
            self.assertIn(("start", "example.service"), commands)
            second = handler_module.Handler(invocation("serviceManagement", "realize", value, "changed", {}), "unused", units, state)
            second.manager = manager
            second.service("apply")
            self.assertIn(("reload-or-restart", "example.service"), commands)
            self.assertEqual(second.service("observe")["status"], "current")
            second.service("remove")
            self.assertFalse((units / "example.service").exists())

    def test_image_owned_service_is_never_started(self):
        with tempfile.TemporaryDirectory() as root:
            value = dict(service(), activation_owner="image")
            instance = handler_module.Handler(invocation("serviceManagement", "realize", value), "unused", root, Path(root) / "state")
            calls = []
            instance.manager = lambda *args, **kwargs: calls.append(args)
            instance.service("apply")
            self.assertEqual(calls, [("daemon-reload",)])

    def test_socket_activation_and_install_links_are_rendered(self):
        value = service()
        value["socket_activation"] = {"sockets": [{"name": "bus", "manager_name": "dbus", "enabled": True, "endpoints": [{"kind": "unix", "path": "/run/dbus/system_bus_socket"}], "mode": "0666", "remove_on_stop": False}]}
        realized = handler_module.realize_service(value)
        self.assertIn('ListenStream="/run/dbus/system_bus_socket"', realized["units"]["dbus.socket"])
        self.assertEqual(realized["links"]["sockets.target.wants/dbus.socket"], "../dbus.socket")

    def test_pending_configuration_can_reconcile_after_crash(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "file"
            path.write_text("prior")
            value = {"path": str(path), "content": "next", "mode": "0644"}
            instance = handler_module.Handler(invocation("configuration", "file", value), "unused", root, Path(root) / "state")
            instance.save({"kind": "configuration", "path": str(path), "digest": handler_module.digest(b"next"), "previous_digest": handler_module.digest(b"prior"), "pending": True})
            self.assertEqual(instance.file("observe")["status"], "retry-safe")

    def test_pending_service_dispatch_is_not_blindly_repeated(self):
        with tempfile.TemporaryDirectory() as root:
            value = service()
            instance = handler_module.Handler(invocation("serviceManagement", "realize", value), "unused", root, Path(root) / "state")
            rendered = handler_module.realize_service(value)
            for name, contents in rendered["units"].items():
                handler_module.durable_write(Path(root) / name, contents.encode())
            instance.save({"kind": "service", "units": {name: handler_module.digest(contents.encode()) for name, contents in rendered["units"].items()}, "pending": True, "dispatching": True, "prior_start": "100"})
            instance.manager = lambda *args, **kwargs: subprocess.CompletedProcess(args, 0, "ActiveState=inactive\nResult=success\nExecMainStartTimestampMonotonic=100\nExecMainExitTimestampMonotonic=150\n", "")
            self.assertEqual(instance.service("observe")["status"], "indeterminate")
            instance.manager = lambda *args, **kwargs: subprocess.CompletedProcess(args, 0, "ActiveState=inactive\nResult=success\nExecMainStartTimestampMonotonic=200\nExecMainExitTimestampMonotonic=250\n", "")
            self.assertEqual(instance.service("observe")["status"], "current")

    def test_directory_units_keep_independent_owners_and_modes(self):
        handler_module.TRUE_EXECUTABLE = "/nix/store/example-coreutils/bin/true"
        value = service()
        value["directories"] = {"managed": [{"path": "example/state", "purpose": "state", "mode": "0750", "retention": "persistent", "owner": "state-owner", "group": "state-group"}]}
        units = handler_module.realize_service(value)["units"]
        directory = next(text for name, text in units.items() if name != "example.service")
        self.assertIn("User=state-owner", directory)
        self.assertIn("Group=state-group", directory)
        self.assertIn("StateDirectoryMode=0750", directory)
        self.assertIn('StateDirectory="example/state"', directory)

    def test_typed_instance_keys_prevent_default_service_collisions(self):
        first = dict(service(), service="main", instance="first.main")
        second = dict(service(), service="main", instance="second.main")
        self.assertNotEqual(handler_module.service_identity(first), handler_module.service_identity(second))

    def test_configuration_receipts_reject_other_scope_ownership(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "file"
            value = {"path": str(path), "content": "shared", "mode": "0644"}
            first = handler_module.Handler(invocation("configuration", "file", value), "unused", root, Path(root) / "state")
            first.file("apply")
            other = dict(invocation("configuration", "file", value), id="other-scope")
            second = handler_module.Handler(other, "unused", root, Path(root) / "state")
            with self.assertRaisesRegex(ValueError, "another installation effect"):
                second.file("apply")

    def test_configuration_views_are_not_interpreted_as_environment_files(self):
        value = service()
        value["configuration"] = {"views": [{"name": "settings", "source": "/etc/example.json", "optional": False}]}
        text = handler_module.realize_service(value)["units"]["example.service"]
        self.assertIn('ReadOnlyPaths="/etc/example.json"', text)
        self.assertNotIn("EnvironmentFile=", text)

    def test_configuration_path_move_retains_old_path_through_a_retry(self):
        with tempfile.TemporaryDirectory() as root:
            old_path = Path(root) / "old.conf"
            new_path = Path(root) / "new.conf"
            old_path.write_text("old")
            new_path.write_text("new")
            value = {"path": str(new_path), "content": "new", "mode": "0600"}
            instance = handler_module.Handler(invocation("configuration", "file", value), "unused", root, Path(root) / "state")
            instance.save({
                "kind": "configuration", "path": str(new_path), "pending": True,
                "digest": handler_module.digest(b"new"),
                "previous_digest": None, "previous_path": str(old_path),
                "previous_path_digest": handler_module.digest(b"old"),
            })

            instance.file("apply")

            self.assertFalse(old_path.exists())
            self.assertEqual(new_path.read_text(), "new")
            self.assertEqual(instance.file("observe")["status"], "current")

    def test_activation_link_drift_is_observed_and_safe_absence_is_repaired(self):
        with tempfile.TemporaryDirectory() as root:
            value = dict(service(), activation_owner="manager")
            instance = handler_module.Handler(invocation("serviceManagement", "realize", value), "unused", root, Path(root) / "state")
            instance.manager = lambda *args, **kwargs: subprocess.CompletedProcess(args, 0, "", "")
            instance.service("apply")
            link = Path(root) / "multi-user.target.wants/example.service"
            link.unlink()

            self.assertEqual(instance.service("observe")["status"], "retry-safe")
            instance.service("apply")
            self.assertTrue(link.is_symlink())

            link.unlink()
            link.symlink_to("../external.service")
            self.assertEqual(instance.service("observe")["status"], "indeterminate")
            with self.assertRaises(ValueError):
                instance.service("remove")

    def test_file_metadata_drift_requires_reconciliation(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "file"
            value = {"path": str(path), "content": "data", "mode": "0600"}
            instance = handler_module.Handler(invocation("configuration", "file", value), "unused", root, Path(root) / "state")
            instance.file("apply")
            path.chmod(0o644)

            self.assertEqual(instance.file("observe")["status"], "retry-safe")
            instance.file("apply")
            self.assertEqual(instance.file("observe")["status"], "current")

    def test_pending_path_move_removal_cleans_both_owned_destinations(self):
        with tempfile.TemporaryDirectory() as root:
            old_path = Path(root) / "old.conf"
            new_path = Path(root) / "new.conf"
            old_path.write_text("old")
            new_path.write_text("new")
            value = {"path": str(new_path), "content": "new", "mode": "0600"}
            instance = handler_module.Handler(invocation("configuration", "file", value), "unused", root, Path(root) / "state")
            instance.save({
                "kind": "configuration", "path": str(new_path), "pending": True,
                "digest": handler_module.digest(b"new"),
                "previous_digest": None, "previous_path": str(old_path),
                "previous_path_digest": handler_module.digest(b"old"),
            })

            instance.file("remove")

            self.assertFalse(old_path.exists())
            self.assertFalse(new_path.exists())
            self.assertFalse(instance.receipt_path.exists())

    def test_remove_observation_retries_owned_configuration_then_proves_absence(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "example.conf"
            value = {"path": str(path), "content": "owned", "mode": "0600"}
            state = Path(root) / "state"
            instance = handler_module.Handler(invocation("configuration", "file", value), "unused", root, state)
            instance.file("apply")
            removal = invocation("configuration", "file", value)
            removal["action"] = "remove"
            recovered = handler_module.Handler(removal, "unused", root, state)

            self.assertEqual(recovered.file("observe")["status"], "retry-safe")
            recovered.file("remove")
            settled = handler_module.Handler(removal, "unused", root, state)
            self.assertEqual(settled.file("observe")["status"], "absent")

    def test_remove_observation_never_repeats_an_uncertain_stop(self):
        with tempfile.TemporaryDirectory() as root:
            value = dict(service(), auto_start=False)
            state = Path(root) / "state"
            instance = handler_module.Handler(invocation("serviceManagement", "realize", value), "unused", root, state)
            instance.manager = lambda *args, **kwargs: subprocess.CompletedProcess(args, 0, "", "")
            instance.service("apply")
            removal = invocation("serviceManagement", "realize", value)
            removal["action"] = "remove"
            recovered = handler_module.Handler(removal, "unused", root, state)

            self.assertEqual(recovered.service("observe")["status"], "retry-safe")

            def fail_stop(*args, **kwargs):
                raise RuntimeError("unknown partial stop")

            recovered.manager = fail_stop
            with self.assertRaises(RuntimeError):
                recovered.service("remove")
            pending = handler_module.Handler(removal, "unused", root, state)
            self.assertEqual(pending.service("observe")["status"], "indeterminate")
            self.assertTrue((Path(root) / "example.service").exists())

    def test_mac_enforcement_uses_an_actual_state_condition(self):
        handler_module.MAC_CONDITION_EXECUTABLE = "/nix/store/service/bin/aos-service-handler"
        value = service()
        value["conditions"] = {"all": [{"kind": "mandatory-access-control", "state": "enforcing", "negated": True}]}

        text = handler_module.realize_service(value)["units"]["example.service"]

        self.assertIn('ExecCondition="/nix/store/service/bin/aos-service-handler" "check-mac" "--negated"', text)
        self.assertNotIn("selinux-enforcing", text)

    def test_configuration_fingerprints_are_not_manager_unit_dependencies(self):
        value = service()
        value["dependencies"] = {"after": ["configuration:path-hash:content-hash", "dbus.service"]}
        text = handler_module.realize_service(value)["units"]["example.service"]
        self.assertIn("After=dbus.service", text)
        self.assertNotIn("configuration:path-hash", text)

    def test_template_identity_uses_the_declared_template_name(self):
        value = dict(service(), instantiation={"kind": "template", "template": "worker"})
        self.assertEqual(handler_module.service_identity(value), "worker@.service")

    def test_environment_preserves_literal_dollars_without_exec_expansion(self):
        value = service()
        value["environment"] = {"variables": {"PASSWORD": "$value%literal"}, "search_path": []}
        text = handler_module.realize_service(value)["units"]["example.service"]
        self.assertIn('Environment="PASSWORD=$value%%literal"', text)


if __name__ == "__main__":
    unittest.main()
