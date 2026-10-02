"""Exercises native service reconciliation without changing host resources."""

import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import tomllib
from types import SimpleNamespace
import unittest
from unittest.mock import patch


handler_path = Path(sys.argv.pop(1)) if len(sys.argv) > 1 else Path(__file__).parents[2] / "pkgs/system/_systemd-abilities/service-handler.py"
configuration_path = Path(sys.argv.pop(1)) if len(sys.argv) > 1 else Path(__file__).parents[2] / "pkgs/system/_aos-configuration-provider/aos_configuration.py"
configuration_entrypoint = Path(sys.argv.pop(1)) if len(sys.argv) > 1 else configuration_path.parent / "handler.py"
configuration_wrapper = Path(sys.argv.pop(1)) if len(sys.argv) > 1 else None
systemd_analyze = Path(sys.argv.pop(1)) if len(sys.argv) > 1 else None
host_activation_input = Path(sys.argv.pop(1)) if len(sys.argv) > 1 else None
package_convergence_input = Path(sys.argv.pop(1)) if len(sys.argv) > 1 else None
projected_service_input = Path(sys.argv.pop(1)) if len(sys.argv) > 1 else None
projected_service_units = Path(sys.argv.pop(1)) if len(sys.argv) > 1 else None
configuration_spec = importlib.util.spec_from_file_location("aos_configuration", configuration_path)
configuration_module = importlib.util.module_from_spec(configuration_spec)
sys.modules["aos_configuration"] = configuration_module
configuration_spec.loader.exec_module(configuration_module)

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


def hardening_policy(profile="privileged"):
    return {
        "privilege_bounds": {"kind": "unrestricted", "privileges": []},
        "ambient_privileges": [], "operation_allow": [], "operation_deny": [],
        "resource_control_delegation": False, "resource_control_access": "host",
        "device_access_scope": "shared", "host_clock_mutation": True,
        "host_name_mutation": True, "operating_system_log_access": True,
        "operating_system_extension_access": True, "operating_system_tunable_access": True,
        "writable_executable_memory": True, "permit_realtime": True,
        "permit_elevated_file_identity": True, "lock_execution_personality": False,
        "isolation_domains": [], "network_families": [],
        "isolation_domain_creation": "allowed", "memory_pressure_adjustment": 0,
        "process_visibility": "all", "operation_architectures": [],
        "operation_profile": profile, "denied_operation_action": "kill-process",
        "allow_privilege_escalation": True,
    }


def bootstrap_bus():
    value = dict(service(), service="dbus", bootstrap=True)
    value["policy"] = {"hardening": hardening_policy()}
    value["manager_identity"] = {"name": "dbus", "aliases": ["messagebus"]}
    value["socket_activation"] = {"sockets": [{
        "name": "system-bus", "manager_name": "dbus", "enabled": True,
        "endpoints": [{"kind": "unix", "path": "/run/dbus/system_bus_socket"}],
        "mode": "0666", "remove_on_stop": False,
    }]}
    return value


def active_bus_manager(calls):
    def manager(*args, **kwargs):
        calls.append(args)
        output = "active\n" if "--value" in args else (
            "ActiveState=active\nResult=success\n"
            "ExecMainStartTimestampMonotonic=100\nExecMainExitTimestampMonotonic=0\n"
        )
        return subprocess.CompletedProcess(args, 0, output, "")
    return manager


class NativeHandlerTests(unittest.TestCase):
    def test_host_activator_publishes_mounts_in_the_manager_namespace(self):
        self.assertIsNotNone(host_activation_input, "requires the actual host activator projection")
        value = json.loads(host_activation_input.read_text())

        text = handler_module.realize_service(value)["units"]["aos-activate.service"]
        directives = dict(line.split("=", 1) for line in text.splitlines() if "=" in line)

        self.assertEqual(directives["PrivateTmp"], "no")
        self.assertEqual(directives["ProtectSystem"], "no")
        self.assertEqual(directives["ProtectHome"], "no")
        self.assertEqual(directives["NoNewPrivileges"], "no")
        for directive in [
            "PrivateMounts", "RootDirectory", "RootImage", "MountFlags",
            "BindPaths", "BindReadOnlyPaths", "ReadOnlyPaths", "ReadWritePaths",
            "InaccessiblePaths", "TemporaryFileSystem", "RuntimeDirectory",
            "StateDirectory", "CacheDirectory", "LogsDirectory", "ConfigurationDirectory",
        ]:
            with self.subTest(directive=directive):
                self.assertNotIn(directive, directives)

    def test_package_convergence_retains_native_host_executor_authority(self):
        self.assertIsNotNone(package_convergence_input, "requires the actual package convergence projection")
        value = json.loads(package_convergence_input.read_text())

        text = handler_module.realize_service(value)["units"]["package-profile-convergence.service"]
        directives = dict(line.split("=", 1) for line in text.splitlines() if "=" in line)

        for directive in ["PrivateTmp", "ProtectSystem", "ProtectHome", "NoNewPrivileges"]:
            with self.subTest(directive=directive):
                self.assertEqual(directives[directive], "no")
        for directive in [
            "PrivateMounts", "PrivateDevices", "RootDirectory", "RootImage",
            "BindPaths", "BindReadOnlyPaths", "ReadOnlyPaths", "ReadWritePaths",
            "InaccessiblePaths", "TemporaryFileSystem", "CapabilityBoundingSet",
            "RestrictNamespaces", "SystemCallFilter", "ProtectControlGroups",
            "ProtectKernelTunables", "ProtectKernelModules",
        ]:
            with self.subTest(directive=directive):
                self.assertNotIn(directive, directives)
        self.assertIn('/bin/apm" "install" "--system" "--from" "/run/apm/package-profile-desired.toml" "--yes"', directives["ExecStart"])
        self.assertIn("After=aos-activate.service", text)
        self.assertIn("Requires=aos-registry-sync.service", text)
        self.assertEqual(directives["TimeoutStartSec"], "120000ms")

    def projected_service(self, root):
        self.assertIsNotNone(projected_service_input, "requires the actual bootstrap operation projection")
        self.assertIsNotNone(projected_service_units, "requires immutable units from the actual renderer")
        value = json.loads(projected_service_input.read_text())
        rendered = handler_module.realize_service(value)
        units = Path(root) / "units"
        units.mkdir()
        originals = {}
        for name, text in rendered["units"].items():
            target = projected_service_units / name
            self.assertEqual(target.read_bytes(), text.encode())
            (units / name).symlink_to(target)
            originals[name] = target.read_bytes()
        for name, target in rendered["links"].items():
            path = units / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.symlink_to(target)
        instance = handler_module.Handler(
            invocation("serviceManagement", "realize", value), "unused", units, Path(root) / "state",
        )
        calls = []
        instance.manager = active_bus_manager(calls)
        return value, rendered, instance, calls, originals

    def test_image_projection_converts_exact_aliases_then_removes_only_namespace_entries(self):
        with tempfile.TemporaryDirectory() as root:
            value, rendered, instance, calls, originals = self.projected_service(root)

            instance.service("apply")

            self.assertEqual(instance.service("observe")["status"], "current")
            self.assertEqual(instance.receipt["image_units"], {})
            for name in rendered["units"]:
                self.assertFalse((instance.unit_directory / name).is_symlink())
                self.assertEqual((instance.unit_directory / name).read_bytes(), originals[name])
            self.assertEqual(instance.receipt["id"], instance.invocation["id"])
            self.assertEqual(instance.receipt["revision"], "first")
            self.assertTrue(instance.links_match(rendered["links"]))

            instance.service("remove")

            for name in rendered["units"] | rendered["links"]:
                self.assertFalse((instance.unit_directory / name).exists())
                self.assertFalse((instance.unit_directory / name).is_symlink())
            self.assertEqual(originals, {name: (projected_service_units / name).read_bytes() for name in originals})
            self.assertFalse(instance.receipt_path.exists())
            instance.invocation["action"] = "remove"
            self.assertEqual(instance.service("observe")["status"], "absent")

    def test_image_projection_update_recovers_pending_replacement_without_mutating_source(self):
        with tempfile.TemporaryDirectory() as root:
            value, rendered, initial, calls, originals = self.projected_service(root)
            previous = initial.service("apply")
            changed = dict(value, lifecycle=dict(value["lifecycle"], description="Changed authenticated service"))
            document = invocation("serviceManagement", "realize", changed, "changed", previous)
            updated = handler_module.Handler(document, "unused", initial.unit_directory, initial.state_directory)
            updated.manager = active_bus_manager(calls)
            original_write = handler_module.durable_write

            def interrupted_write(path, contents, *args):
                original_write(path, contents, *args)
                if Path(path).parent == updated.unit_directory:
                    raise RuntimeError("interrupted after durable unit replacement")

            with patch.object(handler_module, "durable_write", interrupted_write):
                with self.assertRaisesRegex(RuntimeError, "durable unit replacement"):
                    updated.service("apply")

            recovered = handler_module.Handler(document, "unused", initial.unit_directory, initial.state_directory)
            recovered.manager = active_bus_manager(calls)
            self.assertTrue(recovered.receipt["pending"])
            self.assertEqual(recovered.service("observe")["status"], "retry-safe")
            recovered.service("apply")

            self.assertEqual(recovered.service("observe")["status"], "current")
            self.assertFalse(recovered.receipt["pending"])
            main = rendered["resource"]
            self.assertFalse((recovered.unit_directory / main).is_symlink())
            self.assertIn("Changed authenticated service", (recovered.unit_directory / main).read_text())
            self.assertEqual(originals, {name: (projected_service_units / name).read_bytes() for name in originals})
            recovered.service("remove")
            self.assertFalse((recovered.unit_directory / main).exists())

    def test_image_projection_interrupted_before_conversion_retains_exact_pending_custody(self):
        with tempfile.TemporaryDirectory() as root:
            value, rendered, instance, calls, originals = self.projected_service(root)
            original_write = handler_module.durable_write

            def interrupted_write(path, contents, *args):
                if Path(path).parent == instance.unit_directory:
                    raise RuntimeError("interrupted before unit conversion")
                return original_write(path, contents, *args)

            with patch.object(handler_module, "durable_write", interrupted_write):
                with self.assertRaisesRegex(RuntimeError, "before unit conversion"):
                    instance.service("apply")

            recovered = handler_module.Handler(instance.invocation, "unused", instance.unit_directory, instance.state_directory)
            recovered.manager = active_bus_manager(calls)
            self.assertTrue(recovered.receipt["pending"])
            for name in rendered["units"]:
                self.assertTrue((instance.unit_directory / name).is_symlink())
                self.assertEqual(recovered.receipt["image_units"][name], {
                    "target": str(projected_service_units / name),
                    "digest": handler_module.digest(originals[name]),
                })
            with patch.object(handler_module, "image_unit_digest", side_effect=FileNotFoundError("pending source disappeared")):
                self.assertEqual(recovered.service("observe")["status"], "indeterminate")
                with self.assertRaises(FileNotFoundError):
                    recovered.service("apply")
            self.assertEqual(recovered.service("observe")["status"], "retry-safe")
            recovered.service("apply")
            self.assertEqual(recovered.service("observe")["status"], "current")
            self.assertEqual(recovered.receipt["image_units"], {})

    def test_owned_projection_no_longer_depends_on_original_store_target(self):
        with tempfile.TemporaryDirectory() as root:
            value, rendered, instance, calls, originals = self.projected_service(root)
            instance.service("apply")
            changed = dict(value, lifecycle=dict(value["lifecycle"], description="Owned update"))
            updated = handler_module.Handler(
                invocation("serviceManagement", "realize", changed, "changed", instance.service("apply")),
                "unused", instance.unit_directory, instance.state_directory,
            )
            updated.manager = active_bus_manager(calls)

            # Simulate GC of the old immutable source without deleting the
            # shared fixture. Completed ownership must never query it again.
            with patch.object(handler_module, "image_unit_digest", side_effect=FileNotFoundError("old image source collected")):
                self.assertEqual(instance.service("observe")["status"], "current")
                updated.service("apply")
                self.assertEqual(updated.service("observe")["status"], "current")
                updated.service("remove")
            self.assertEqual(originals, {name: (projected_service_units / name).read_bytes() for name in originals})

    def test_image_projection_rejects_unselected_mutable_and_changed_aliases(self):
        with tempfile.TemporaryDirectory() as root:
            value, rendered, initial, calls, originals = self.projected_service(root)
            ordinary = dict(value, bootstrap=False)
            unselected = handler_module.Handler(
                invocation("serviceManagement", "realize", ordinary), "unused", initial.unit_directory, initial.state_directory,
            )
            with self.assertRaisesRegex(ValueError, "no authenticated image projection"):
                unselected.service("apply")
            self.assertIsNone(unselected.receipt)

            mismatched = dict(value, lifecycle=dict(value["lifecycle"], description="Different authenticated content"))
            mismatch = handler_module.Handler(
                invocation("serviceManagement", "realize", mismatched), "unused", initial.unit_directory, initial.state_directory,
            )
            with self.assertRaisesRegex(ValueError, "conflicts with authenticated rendered content"):
                mismatch.service("apply")
            self.assertIsNone(mismatch.receipt)

            main = rendered["resource"]
            mutable = Path(root) / "mutable.service"
            mutable.write_bytes(originals[main])
            leaf = initial.unit_directory / main
            leaf.unlink()
            leaf.symlink_to(mutable)
            with self.assertRaisesRegex(ValueError, "canonical immutable store member"):
                initial.service("apply")
            self.assertIsNone(initial.receipt)
            self.assertEqual(calls, [])

            leaf.unlink()
            leaf.symlink_to(projected_service_units / main)
            initial.service("apply")
            saved_receipt = initial.receipt_path.read_bytes()
            leaf.unlink()
            leaf.symlink_to(projected_service_units / main)
            for action in ["apply", "remove"]:
                with self.subTest(action=action), self.assertRaisesRegex(ValueError, "replaced by an external link"):
                    initial.service(action)
            self.assertEqual(initial.service("observe")["status"], "indeterminate")
            self.assertEqual(initial.receipt_path.read_bytes(), saved_receipt)
            self.assertEqual(originals, {name: (projected_service_units / name).read_bytes() for name in originals})

    def test_workload_profiles_preserve_master_syscall_filters(self):
        for profile, expected in [
            ("privileged", []),
            ("restricted", ["SystemCallFilter=@system-service"]),
            ("system-service", ["SystemCallFilter=@system-service"]),
        ]:
            with self.subTest(profile=profile):
                value = service()
                policy = hardening_policy(profile)
                policy["denied_operation_action"] = "return-permission-denied"
                value["policy"] = {"hardening": policy}

                rendered = handler_module.realize_service(value)["units"]["example.service"]

                filters = [line for line in rendered.splitlines() if line.startswith("SystemCallFilter=")]
                self.assertEqual(filters, expected)
                self.assertIn("SystemCallErrorNumber=EPERM", rendered)

    def test_explicit_syscall_exceptions_follow_profile_and_exclusions(self):
        value = service()
        policy = hardening_policy("system-service")
        policy["operation_deny"] = ["privileged", "mount"]
        policy["operation_allow"] = ["clock", "change-file-ownership"]
        value["policy"] = {"hardening": policy}

        rendered = handler_module.realize_service(value)["units"]["example.service"]

        filters = [line for line in rendered.splitlines() if line.startswith("SystemCallFilter=")]
        self.assertEqual(filters, [
            "SystemCallFilter=@system-service",
            "SystemCallFilter=~@privileged @mount",
            "SystemCallFilter=@clock @chown",
        ])
        self.assertNotIn("SystemCallErrorNumber=", rendered)

    def test_manager_observer_projection_preserves_native_units_and_enablement_links(self):
        services = {
            key: dict(
                service(), service=name, activation_owner="manager", auto_start=False,
            )
            for key, name in {
                "ability-crucible.adapter": "aos-ability-crucible",
                "boundary-observer.controller": "aos-ability-boundary-controller",
            }.items()
        }
        expected_links = {
            f"multi-user.target.wants/{name}.service": f"../{name}.service"
            for name in ["aos-ability-crucible", "aos-ability-boundary-controller"]
        }

        with tempfile.TemporaryDirectory() as root:
            units = Path(root) / "units"
            handler_module.render_services(services, units)

            native_links = {}
            for value in services.values():
                rendered = handler_module.realize_service(value)
                native_links.update(rendered["links"])
                for name, text in rendered["units"].items():
                    self.assertEqual((units / name).read_bytes(), text.encode())
            image_links = {
                str(path.relative_to(units)): os.readlink(path)
                for path in units.rglob("*") if path.is_symlink()
            }

            self.assertEqual(native_links, expected_links)
            self.assertEqual(image_links, native_links)

    def test_bootstrap_bus_adopts_exact_units_and_links_without_restart(self):
        with tempfile.TemporaryDirectory() as root:
            units = Path(root) / "units"
            state = Path(root) / "state"
            value = bootstrap_bus()
            handler_module.render_services({"dbus": value}, units)
            rendered = handler_module.realize_service(value)
            before = {name: (units / name).read_bytes() for name in rendered["units"]}
            instance = handler_module.Handler(
                invocation("serviceManagement", "realize", value), "unused", units, state,
            )
            calls = []
            instance.manager = active_bus_manager(calls)

            result = instance.service("apply")

            self.assertEqual(result["resource"], "dbus.service")
            self.assertEqual(instance.receipt["owner"], "ability")
            self.assertFalse(instance.receipt["pending"])
            self.assertEqual(before, {name: (units / name).read_bytes() for name in rendered["units"]})
            self.assertTrue(instance.links_match(rendered["links"]))
            self.assertFalse(any(call[0] in {"restart", "reload-or-restart", "stop"} for call in calls))
            self.assertEqual(instance.service("observe")["status"], "current")

    def test_adopted_bus_configuration_revision_reloads_without_changing_unit_bytes(self):
        with tempfile.TemporaryDirectory() as root:
            units = Path(root) / "units"
            state = Path(root) / "state"
            value = dict(bootstrap_bus(), dependencyValues=["configuration:dbus:first"])
            handler_module.render_services({"dbus": value}, units)
            initial = handler_module.Handler(
                invocation("serviceManagement", "realize", value), "unused", units, state,
            )
            calls = []
            initial.manager = active_bus_manager(calls)
            previous = initial.service("apply")
            original_bytes = (units / "dbus.service").read_bytes()
            updated_value = dict(value, dependencyValues=["configuration:dbus:changed"])
            updated = handler_module.Handler(
                invocation("serviceManagement", "realize", updated_value, "changed", previous),
                "unused", units, state,
            )
            calls.clear()
            updated.manager = active_bus_manager(calls)

            updated.service("apply")

            self.assertEqual(calls.count(("reload-or-restart", "dbus.service")), 1)
            self.assertEqual((units / "dbus.service").read_bytes(), original_bytes)
            self.assertEqual(updated.service("observe")["status"], "current")

    def test_bootstrap_bus_rejects_external_unit_drift_before_adoption(self):
        with tempfile.TemporaryDirectory() as root:
            units = Path(root) / "units"
            value = bootstrap_bus()
            handler_module.render_services({"dbus": value}, units)
            (units / "dbus.service").write_text("[Service]\nExecStart=/external\n")
            instance = handler_module.Handler(
                invocation("serviceManagement", "realize", value), "unused", units, Path(root) / "state",
            )
            calls = []
            instance.manager = active_bus_manager(calls)

            with self.assertRaisesRegex(ValueError, "conflicts with external configuration"):
                instance.service("apply")

            self.assertEqual(calls, [])
            self.assertIsNone(instance.receipt)
            self.assertEqual(instance.service("observe")["status"], "indeterminate")

    def test_bootstrap_bus_interrupted_dispatch_retains_uncertainty(self):
        with tempfile.TemporaryDirectory() as root:
            units = Path(root) / "units"
            state = Path(root) / "state"
            value = bootstrap_bus()
            document = invocation("serviceManagement", "realize", value)
            handler_module.render_services({"dbus": value}, units)
            instance = handler_module.Handler(document, "unused", units, state)
            calls = []
            delegate = active_bus_manager(calls)

            def interrupted_manager(*args, **kwargs):
                result = delegate(*args, **kwargs)
                if args == ("start", "dbus.service"):
                    raise RuntimeError("manager response interrupted after dispatch")
                return result

            instance.manager = interrupted_manager

            with self.assertRaisesRegex(RuntimeError, "response interrupted"):
                instance.service("apply")

            recovered = handler_module.Handler(document, "unused", units, state)
            self.assertTrue(recovered.receipt["pending"])
            self.assertTrue(recovered.receipt["dispatching"])
            calls.clear()
            recovered.manager = active_bus_manager(calls)

            self.assertEqual(recovered.service("observe")["status"], "indeterminate")
            self.assertTrue(all(call[0] == "show" for call in calls))
            self.assertTrue(recovered.receipt["pending"])

    def test_required_character_device_is_present(self):
        with tempfile.TemporaryDirectory() as root:
            instance = handler_module.Handler(
                invocation("device", "present", {"path": "/dev/null"}),
                "unused", root, Path(root) / "state",
            )

            self.assertEqual(instance.device("apply"), {"resource": "/dev/null"})
            self.assertEqual(instance.device("observe")["status"], "current")

    def test_required_block_device_is_present(self):
        with tempfile.TemporaryDirectory() as root:
            value = {"path": "/dev/fixture-block", "kind": "block"}
            instance = handler_module.Handler(
                invocation("device", "present", value),
                "unused", root, Path(root) / "state",
            )

            # Unit coverage does not create privileged device nodes on the host.
            block_stat = SimpleNamespace(st_mode=stat.S_IFBLK | 0o600)
            with patch.object(handler_module.os, "stat", return_value=block_stat):
                self.assertEqual(instance.device("apply"), {"resource": value["path"]})
                self.assertEqual(instance.device("observe")["status"], "current")

    def test_required_device_rejects_wrong_kind_and_regular_files(self):
        with tempfile.TemporaryDirectory() as root:
            ordinary = Path(root) / "ordinary"
            ordinary.write_text("not a device")
            wrong_nodes = [
                ("/dev/null", "block"),
                (str(ordinary), "character"),
                (str(ordinary), "block"),
            ]

            for path, kind in wrong_nodes:
                with self.subTest(path=path, kind=kind):
                    value = {"path": path, "kind": kind}
                    instance = handler_module.Handler(
                        invocation("device", "present", value),
                        "unused", root, Path(root) / "state",
                    )

                    with self.assertRaisesRegex(ValueError, "wrong kind"):
                        instance.device("apply")
                    self.assertEqual(instance.device("observe")["status"], "retry-safe")

    def test_required_device_rejects_absent_path(self):
        with tempfile.TemporaryDirectory() as root:
            for kind in ["character", "block"]:
                with self.subTest(kind=kind):
                    value = {"path": str(Path(root) / "missing"), "kind": kind}
                    instance = handler_module.Handler(
                        invocation("device", "present", value),
                        "unused", root, Path(root) / "state",
                    )

                    with self.assertRaisesRegex(ValueError, "absent"):
                        instance.device("apply")
                    self.assertEqual(instance.device("observe")["status"], "retry-safe")

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
        self.assertIn('ListenStream=/run/dbus/system_bus_socket', realized["units"]["dbus.socket"])
        self.assertEqual(realized["links"]["sockets.target.wants/dbus.socket"], "../dbus.socket")

    @unittest.skipUnless(systemd_analyze, "pinned systemd-analyze executable not supplied")
    def test_rendered_socket_units_pass_pinned_manager_parser(self):
        value = bootstrap_bus()
        value["lifecycle"]["start"] = [{
            "executable": {"path": str(systemd_analyze), "arguments": ["--version"]},
            "ignore_failure": False,
        }]
        value["directories"] = {"managed": [{
            "path": "dbus", "purpose": purpose, "mode": "0755", "retention": "persistent",
        } for purpose in ("runtime", "state")]}
        value["socket_activation"]["sockets"][0]["endpoints"] += [
            {"kind": "unix", "path": "/run/aos-test/socket %literal"},
            {"kind": "network", "address": "127.0.0.1", "port": 45000, "transport": "tcp"},
            {"kind": "network", "address": "::1", "port": 45001, "transport": "udp"},
        ]

        with tempfile.TemporaryDirectory() as root:
            units = Path(root) / "units"
            with patch.object(handler_module, "TRUE_EXECUTABLE", str(systemd_analyze)):
                handler_module.render_services({"dbus": value}, units)
            vendor_units = systemd_analyze.parent.parent / "lib/systemd/system"
            environment = dict(os.environ, SYSTEMD_UNIT_PATH=f"{units}:{vendor_units}",
                               SYSTEMD_LOG_COLOR="0", SYSTEMD_LOG_LEVEL="warning")
            unit_paths = sorted(str(path) for path in units.iterdir() if path.suffix in {".service", ".socket"})

            verified = subprocess.run(
                [str(systemd_analyze), "--man=no", "--generators=no", "verify", *unit_paths],
                env=environment, capture_output=True, text=True, check=False,
            )

            self.assertEqual(verified.returncode, 0, verified.stdout + verified.stderr)
            self.assertNotIn("Failed to parse", verified.stderr)
            socket = (units / "dbus.socket").read_text()
            self.assertIn("ListenStream=/run/dbus/system_bus_socket\n", socket)
            self.assertIn("ListenStream=/run/aos-test/socket %%literal\n", socket)
            self.assertIn("ListenStream=127.0.0.1:45000\n", socket)
            self.assertIn("ListenDatagram=[::1]:45001\n", socket)

            # Reproduce the old Exec-style quoting so this gate must catch it.
            quoted_lines = []
            for line in socket.splitlines():
                if line.startswith(("ListenStream=", "ListenDatagram=")):
                    key, address = line.split("=", 1)
                    line = f'{key}="{address}"'
                quoted_lines.append(line)
            (units / "dbus.socket").write_text("\n".join(quoted_lines) + "\n")

            rejected = subprocess.run(
                [str(systemd_analyze), "--man=no", "--generators=no", "verify", *unit_paths],
                env=environment, capture_output=True, text=True, check=False,
            )

            self.assertNotEqual(rejected.returncode, 0)
            self.assertIn("Failed to parse address value", rejected.stderr)

    def test_socket_addresses_reject_scalar_injection_and_unrepresentable_suffixes(self):
        for invalid in (
            "/run/test\n[Service]", "/run/test\rInjected=yes", "/run/test\0socket",
            "/run/test\\", "/run/test ",
        ):
            with self.subTest(path=invalid):
                value = bootstrap_bus()
                value["socket_activation"]["sockets"][0]["endpoints"][0]["path"] = invalid

                with self.assertRaises(ValueError):
                    handler_module.realize_service(value)

        for invalid in ("127.0.0.1\n[Service]", "::1\rInjected=yes", "127.0.0.1\0"):
            with self.subTest(address=invalid):
                value = bootstrap_bus()
                value["socket_activation"]["sockets"][0]["endpoints"] = [{
                    "kind": "network", "address": invalid, "port": 45000, "transport": "tcp",
                }]

                with self.assertRaises(ValueError):
                    handler_module.realize_service(value)

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

    def test_managed_directories_remain_writable_in_service_namespace(self):
        purposes = {
            "runtime": ("RuntimeDirectory", "/run/"),
            "state": ("StateDirectory", "/var/lib/"),
            "cache": ("CacheDirectory", "/var/cache/"),
            "logs": ("LogsDirectory", "/var/log/"),
            "configuration": ("ConfigurationDirectory", "/etc/"),
        }
        for purpose, (directive, root) in purposes.items():
            with self.subTest(purpose=purpose):
                value = service()
                value["directories"] = {"managed": [{
                    "path": "example/state", "purpose": purpose, "mode": "0700",
                    "retention": "persistent", "owner": "state-owner", "group": "state-group",
                }]}
                value["isolation"] = {
                    "privilege": "privileged", "filesystem": "read-only-system",
                    "home_access": "inaccessible", "network": "host", "process_visibility": "host",
                    "termination_scope": "all-processes", "temporary_directory": "private",
                    "root_directory": "/srv/service-root",
                    "temporary_filesystems": [{"path": root.rstrip("/"), "read_only": True}],
                    "devices": [], "host_paths": [], "permit_core_dumps": False,
                }

                with patch.object(handler_module, "TRUE_EXECUTABLE", "/nix/store/coreutils/bin/true"):
                    rendered = handler_module.realize_service(value)
                directory_name = next(name for name in rendered["units"] if name != "example.service")
                directory = rendered["units"][directory_name]
                main = rendered["units"]["example.service"]

                self.assertIn(directive + '="example/state"', directory)
                self.assertIn(directive + "Mode=0700", directory)
                self.assertIn("User=state-owner", directory)
                self.assertIn("Group=state-group", directory)
                self.assertIn("Requires=" + directory_name, main)
                self.assertIn("After=" + directory_name, main)
                self.assertIn("ProtectSystem=strict", main)
                self.assertIn('RootDirectory="/srv/service-root"', main)
                self.assertIn('TemporaryFileSystem="' + root.rstrip("/") + ':ro"', main)
                self.assertIn('BindPaths="' + root + 'example/state"', main)
                self.assertNotIn(directive + "=", main)

    def test_managed_public_keys_are_created_before_a_readonly_daemon_view(self):
        value = dict(service(), service="sshd")
        value["directories"] = {"managed": [{
            "path": "ssh/authorized_keys", "purpose": "configuration", "mode": "0755",
            "retention": "persistent", "owner": "root", "group": "root",
        }]}
        value["configuration"] = {"views": [{
            "name": "authorized-keys", "source": "/etc/ssh/authorized_keys", "optional": False,
        }]}

        with patch.object(handler_module, "TRUE_EXECUTABLE", "/nix/store/coreutils/bin/true"):
            rendered = handler_module.realize_service(value)
        main = rendered["units"]["sshd.service"]
        directory_name = next(name for name in rendered["units"] if name != "sshd.service")
        directory = rendered["units"][directory_name]

        self.assertIn('ConfigurationDirectory="ssh/authorized_keys"', directory)
        self.assertIn("ConfigurationDirectoryMode=0755", directory)
        self.assertIn("User=root", directory)
        self.assertIn("Group=root", directory)
        self.assertIn("Before=sshd.service", directory)
        self.assertIn("Requires=" + directory_name, main)
        self.assertIn("After=" + directory_name, main)
        self.assertIn('ReadOnlyPaths="/etc/ssh/authorized_keys"', main)
        self.assertNotIn("ReadOnlyPaths=", directory)
        self.assertNotIn("RuntimeDirectory=", directory)
        self.assertNotIn("BindsTo=", directory)

    def test_registry_state_directory_precedes_sandboxed_bootstrap_service(self):
        value = dict(service(), service="aos-registry-sync", activation_owner="image", auto_start=False)
        value["directories"] = {"managed": [{
            "path": "apm", "purpose": "state", "mode": "0755",
            "retention": "persistent", "owner": "root", "group": "root",
        }]}
        value["isolation"] = {
            "privilege": "privileged", "filesystem": "read-only-system",
            "home_access": "inaccessible", "network": "host", "process_visibility": "host",
            "termination_scope": "all-processes", "temporary_directory": "private",
            "devices": [], "host_paths": [{"source": "/var/lib/apm", "mode": "read-write"}],
            "permit_core_dumps": False,
        }

        with patch.object(handler_module, "TRUE_EXECUTABLE", "/nix/store/coreutils/bin/true"):
            rendered = handler_module.realize_service(value)
        directory_name = next(name for name in rendered["units"] if name != "aos-registry-sync.service")
        directory = rendered["units"][directory_name]
        registry = rendered["units"]["aos-registry-sync.service"]

        self.assertIn('StateDirectory="apm"', directory)
        self.assertIn("StateDirectoryMode=0755", directory)
        self.assertIn("User=root", directory)
        self.assertIn("Group=root", directory)
        self.assertIn("Before=aos-registry-sync.service", directory)
        self.assertIn("Requires=" + directory_name, registry)
        self.assertIn("After=" + directory_name, registry)
        self.assertIn('BindPaths="/var/lib/apm"', registry)

    def test_unnamed_services_use_distinct_domain_instance_keys(self):
        first = dict(service(), service="", instance="first.main")
        second = dict(service(), service="", instance="second.main")
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

    def test_configuration_provider_rejects_service_owned_path(self):
        with tempfile.TemporaryDirectory() as root:
            units = Path(root) / "units"
            state = Path(root) / "state"
            instance = handler_module.Handler(invocation("serviceManagement", "realize", service()), "unused", units, state)
            instance.manager = lambda *args, **kwargs: SimpleNamespace(returncode=0, stdout="", stderr="")
            instance.service("apply")
            path = units / "example.service"
            value = {"path": str(path), "content": path.read_text(), "mode": "0644"}
            other = dict(invocation("configuration", "file", value), id="configuration-owner")
            configuration = handler_module.ConfigurationHandler(other, state)

            with self.assertRaisesRegex(ValueError, "another installation effect"):
                configuration.file("apply")

    def test_service_rejects_configuration_owned_path(self):
        with tempfile.TemporaryDirectory() as root:
            units = Path(root) / "units"
            state = Path(root) / "state"
            rendered = handler_module.realize_service(service())["units"]["example.service"]
            value = {"path": str(units / "example.service"), "content": rendered, "mode": "0644"}
            configuration = handler_module.ConfigurationHandler(invocation("configuration", "file", value), state)
            configuration.file("apply")
            other = dict(invocation("serviceManagement", "realize", service()), id="service-owner")
            instance = handler_module.Handler(other, "unused", units, state)

            with self.assertRaisesRegex(ValueError, "another installation effect"):
                instance.service("apply")

    def test_standalone_configuration_process_needs_no_service_manager(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "configuration"
            state = Path(root) / "state"
            document = invocation("configuration", "file", {"path": str(path), "content": "portable", "mode": "0600"})
            # Reproduce the installed source layout from the exact retained files.
            library = Path(root) / "libexec"
            library.mkdir()
            (library / "aos_configuration.py").write_bytes(configuration_path.read_bytes())
            executable = library / "handler.py"
            executable.write_bytes(configuration_entrypoint.read_bytes())

            def run(action):
                result = subprocess.run(
                    [sys.executable, "-B", str(executable), "--state-directory", str(state), action],
                    input=json.dumps(document), capture_output=True, text=True,
                    env={}, check=True,
                )
                return json.loads(result.stdout)

            self.assertEqual(run("apply")["path"], str(path))
            self.assertEqual(path.read_text(), "portable")
            self.assertEqual(run("observe")["status"], "current")
            path.write_text("external edit")
            self.assertEqual(run("observe")["status"], "indeterminate")
            path.write_text("portable")
            self.assertEqual(run("remove"), {})
            self.assertFalse(path.exists())

    @unittest.skipIf(configuration_wrapper is None, "requires the source-built provider wrapper")
    def test_installed_wrapper_keeps_writable_provider_payload_unchanged(self):
        with tempfile.TemporaryDirectory() as root:
            payload = Path(root) / "provider"
            library = payload / "libexec"
            library.mkdir(parents=True)
            installed_root = configuration_wrapper.parent.parent
            for name in ("handler.py", "aos_configuration.py"):
                (library / name).write_bytes((installed_root / "libexec" / name).read_bytes())
            wrapper = payload / "provider"
            # Relocate only the payload path to reproduce the writable initrd
            # store. Keep the installed wrapper's Python command and flags.
            wrapper.write_text(configuration_wrapper.read_text().replace(str(installed_root), str(payload)))
            wrapper.chmod(0o700)
            before = {path.name: path.read_bytes() for path in library.iterdir()}
            document = invocation("configuration", "file", {
                "path": str(Path(root) / "configuration"), "content": "portable", "mode": "0600",
            })

            subprocess.run(
                [str(wrapper), "--state-directory", str(Path(root) / "state"), "apply"],
                input=json.dumps(document), capture_output=True, text=True, env={}, check=True,
            )

            after = {path.name: path.read_bytes() for path in library.iterdir() if path.is_file()}
            self.assertEqual(after, before)
            self.assertEqual(sorted(path.name for path in library.iterdir()), sorted(before))
            self.assertFalse((library / "__pycache__").exists())

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

    def test_path_conditions_use_scalar_paths_and_literal_specifiers(self):
        value = service()
        value["conditions"] = {"all": [
            {"kind": "path", "predicate": "exists", "path": "/tmp/a path%literal", "negated": True},
            {"kind": "path", "predicate": "is-mount-point", "path": "/run/etc", "negated": False},
        ]}

        text = handler_module.realize_service(value)["units"]["example.service"]

        self.assertIn("ConditionPathExists=!/tmp/a path%%literal\n", text)
        self.assertIn("ConditionPathIsMountPoint=/run/etc\n", text)
        self.assertIn('"a b" "$$USER" "%%i"', text)

        value["conditions"]["all"][0]["path"] = "/tmp/path\nInjected=yes"
        with self.assertRaises(ValueError):
            handler_module.realize_service(value)

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

    def test_service_identity_preserves_declared_name_before_domain_instance(self):
        value = dict(service(), service="tailscaled", instance="tailscale")

        self.assertEqual(handler_module.service_identity(value), "tailscaled.service")
        value["manager_identity"] = {"name": "custom-vpn", "aliases": []}
        self.assertEqual(handler_module.service_identity(value), "custom-vpn.service")
        value.pop("manager_identity")
        value.pop("service")
        self.assertEqual(handler_module.service_identity(value), "tailscale.service")

    def test_no_new_privileges_combines_policy_and_isolation_once(self):
        for policy, isolation, expected in [
            (False, "privileged", "yes"),
            (True, "unprivileged", "yes"),
            (True, "privileged", "no"),
            (None, "unprivileged", "yes"),
        ]:
            with self.subTest(policy=policy, isolation=isolation):
                value = {"isolation": {
                    "privilege": isolation, "network": "host", "temporary_directory": "shared",
                    "filesystem": "host", "home_access": "host", "process_visibility": "host",
                    "termination_scope": "all-processes", "permit_core_dumps": False,
                    "devices": [], "host_paths": [],
                }}
                if policy is not None:
                    value["policy"] = {"hardening": {"allow_privilege_escalation": policy}}
                unit = handler_module.Unit()
                with patch.object(handler_module, "hardening"):
                    handler_module.process_features(unit, value)

                directives = [line for line in unit.sections["Service"] if line.startswith("NoNewPrivileges=")]
                self.assertEqual(directives, ["NoNewPrivileges=" + expected])

    def test_template_identity_uses_the_declared_template_name(self):
        value = dict(service(), instantiation={"kind": "template", "template": "worker"})
        self.assertEqual(handler_module.service_identity(value), "worker@.service")

    def test_search_path_preserves_package_bin_and_sbin_tools(self):
        value = service()
        value["environment"] = {
            "variables": {},
            "search_path": ["/nix/store/bridge-utils", "/nix/store/iptables"],
        }

        text = handler_module.realize_service(value)["units"]["example.service"]

        self.assertIn(
            "ExecSearchPath=/nix/store/bridge-utils/bin:/nix/store/bridge-utils/sbin:"
            "/nix/store/iptables/bin:/nix/store/iptables/sbin",
            text,
        )

    def test_instance_identity_preserves_template_resource(self):
        value = dict(service(), service="ignored", instance="domain.instance")
        value["instantiation"] = {
            "kind": "instance", "template_resource": "worker@.service", "instance": "member",
        }

        self.assertEqual(handler_module.service_identity(value), "worker@member.service")

    def test_environment_preserves_literal_dollars_without_exec_expansion(self):
        value = service()
        value["environment"] = {"variables": {"PASSWORD": "$value%literal"}, "search_path": []}
        text = handler_module.realize_service(value)["units"]["example.service"]
        self.assertIn('Environment="PASSWORD=$value%%literal"', text)


if __name__ == "__main__":
    unittest.main()
