"""Checks bootstrap custody, recovery, and native recipient cutover."""

import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest

SOURCE = Path(__file__).parent
provider = Path(sys.argv.pop(1)) if len(sys.argv) > 1 else SOURCE / "bootstrap-provider.py"
configuration = Path(sys.argv.pop(1)) if len(sys.argv) > 1 else SOURCE.parent / "_aos-configuration-provider" / "aos_configuration.py"
config_spec = importlib.util.spec_from_file_location("aos_configuration", configuration)
config_module = importlib.util.module_from_spec(config_spec)
sys.modules["aos_configuration"] = config_module
config_spec.loader.exec_module(config_module)
spec = importlib.util.spec_from_file_location("bootstrap", provider)
bootstrap = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bootstrap)


class Renderer:
    @staticmethod
    def read_digest(path):
        try:
            if path.is_symlink():
                raise ValueError("unexpected alias")
            return bootstrap.digest(path.read_bytes())
        except FileNotFoundError:
            return None

    @staticmethod
    def image_unit_digest(target):
        return bootstrap.digest(Path(target).read_bytes())


class Harness(bootstrap.Bootstrap):
    def __init__(self, root, revision="first"):
        invocation = {"id": "bootstrap-owner", "revision": revision, "input": {}}
        args = SimpleNamespace(
            state_directory=str(root / "state"), unit_directory=str(root / "units"),
            root_directory=str(root / "gcroots"), service_state_directory=str(root / "services"),
            group_state_directory=str(root / "groups"), nix_store="unused",
        )
        super().__init__(invocation, Renderer, args)
        self.source = root / ("immutable-" + revision)
        self.source.mkdir(exist_ok=True)
        self.text = "[Service]\nExecStart=/retained/broker\n" + revision
        (self.source / "dbus.service").write_text(self.text)
        self.entry = {"kind": "service", "recipient": "service-owner",
                      "digest": bootstrap.digest(self.text.encode()), "link": None,
                      "target": str(self.source / "dbus.service")}

    def render(self):
        return str(self.source), "test-nar-identity", {"dbus.service": self.entry}

    def command(self, *arguments, input=None):
        return "test-nar-identity"

    def recipient_receipt(self, pending=False):
        directory = Path(self.args.service_state_directory)
        directory.mkdir(exist_ok=True)
        receipt = {"id": "service-owner", "units": {"dbus.service": self.entry["digest"]},
                   "links": {}, "pending": pending, "image_units": {}}
        if pending:
            receipt["image_units"]["dbus.service"] = {"target": self.entry["target"], "digest": self.entry["digest"]}
        (directory / (bootstrap.digest(b"service-owner") + ".json")).write_text(json.dumps(receipt))


class BootstrapTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.handler = Harness(self.root)

    def tearDown(self):
        self.temporary.cleanup()

    def test_prepare_observe_and_exact_remove(self):
        outputs = self.handler.apply()

        self.assertEqual(outputs["storePath"], str(self.handler.source))
        self.assertEqual(self.handler.observe()["status"], "current")
        self.assertTrue((self.handler.units / "dbus.service").is_symlink())
        self.assertEqual(len(list(self.handler.roots.iterdir())), 1)

        self.handler.remove()

        self.assertFalse((self.handler.units / "dbus.service").exists())
        self.assertEqual(list(self.handler.roots.iterdir()), [])
        self.assertFalse(self.handler.path.exists())

    def test_foreign_definition_is_never_replaced(self):
        self.handler.units.mkdir()
        path = self.handler.units / "dbus.service"
        path.write_text("foreign")

        with self.assertRaises(ValueError):
            self.handler.apply()

        self.assertEqual(path.read_text(), "foreign")
        self.assertFalse(self.handler.path.exists())

    def test_matching_unowned_alias_is_not_adopted(self):
        self.handler.units.mkdir()
        path = self.handler.units / "dbus.service"
        path.symlink_to(self.handler.entry["target"])

        with self.assertRaises(ValueError):
            self.handler.apply()

        self.assertEqual(os.readlink(path), self.handler.entry["target"])

    def test_recipient_transfer_preserves_regular_file_and_releases_finished_seed(self):
        self.handler.apply()
        path = self.handler.units / "dbus.service"
        path.unlink()
        path.write_text(self.handler.text)
        self.handler.recipient_receipt()

        self.assertEqual(self.handler.observe()["status"], "current")
        self.handler.remove()

        self.assertEqual(path.read_text(), self.handler.text)
        self.assertEqual(list(self.handler.roots.iterdir()), [])

    def test_pending_recipient_keeps_original_seed_root(self):
        self.handler.apply()
        path = self.handler.units / "dbus.service"
        path.unlink()
        path.write_text(self.handler.text)
        self.handler.recipient_receipt(pending=True)

        with self.assertRaises(ValueError):
            self.handler.remove()

        self.assertEqual(path.read_text(), self.handler.text)
        self.assertEqual(len(list(self.handler.roots.iterdir())), 1)
        self.assertTrue(self.handler.path.exists())

    def test_foreign_regular_replacement_requires_the_exact_recipient(self):
        self.handler.apply()
        path = self.handler.units / "dbus.service"
        path.unlink()
        path.write_text(self.handler.text)

        with self.assertRaises(ValueError):
            self.handler.observe()
        with self.assertRaises(ValueError):
            self.handler.remove()

        self.assertEqual(path.read_text(), self.handler.text)
        self.assertEqual(len(list(self.handler.roots.iterdir())), 1)

    def test_receipt_precedes_publication_and_recovers_interrupted_cutover(self):
        self.handler.apply()
        replacement = Harness(self.root, "second")
        original_save = replacement.save

        def fail_after_intent(receipt):
            original_save(receipt)
            if receipt.get("pending"):
                raise OSError("injected publication interruption")

        replacement.save = fail_after_intent
        with self.assertRaises(OSError):
            replacement.apply()
        self.assertEqual(os.readlink(replacement.units / "dbus.service"), self.handler.entry["target"])
        self.assertTrue(json.loads(replacement.path.read_text())["pending"])

        resumed = Harness(self.root, "second")
        self.assertEqual(resumed.observe()["status"], "retry-safe")
        resumed.apply()

        self.assertEqual(resumed.observe()["status"], "current")
        self.assertEqual(os.readlink(resumed.units / "dbus.service"), resumed.entry["target"])

    def test_dropped_adopted_recipient_keeps_custody_across_two_revisions(self):
        self.handler.apply()
        path = self.handler.units / "dbus.service"
        path.unlink()
        path.write_text(self.handler.text)
        self.handler.recipient_receipt(pending=True)

        second = Harness(self.root, "second")
        second.render = lambda: (str(second.source), "test-nar-identity", {})
        second.apply()
        third = Harness(self.root, "third")
        third.render = lambda: (str(third.source), "test-nar-identity", {})
        third.apply()
        with self.assertRaises(ValueError):
            third.remove()

        self.assertEqual(path.read_text(), self.handler.text)

        self.assertEqual(len(list(third.roots.iterdir())), 3)
        self.assertEqual(len(third.receipt["history"]), 1)

        self.handler.recipient_receipt(pending=False)
        third.remove()

        self.assertEqual(list(third.roots.iterdir()), [])
        self.assertEqual(path.read_text(), self.handler.text)

    def test_pending_cutover_can_retire_its_unpublished_predecessor(self):
        self.handler.apply()
        replacement = Harness(self.root, "second")
        original_save = replacement.save

        def fail_after_intent(receipt):
            original_save(receipt)
            if receipt.get("pending"):
                raise OSError("injected publication interruption")

        replacement.save = fail_after_intent
        with self.assertRaises(OSError):
            replacement.apply()

        resumed = Harness(self.root, "second")
        resumed.remove()

        self.assertFalse((resumed.units / "dbus.service").exists())
        self.assertEqual(list(resumed.roots.iterdir()), [])
        self.assertFalse(resumed.path.exists())

    def test_import_is_pinned_before_importer_temporary_root_expires(self):
        class Rendered(Renderer):
            @staticmethod
            def render_services(services, tree):
                tree.mkdir()
                (tree / "dbus.service").write_text("canonical unit")

            @staticmethod
            def realize_service(service):
                return {"units": {"dbus.service": "canonical unit"}, "links": {}}

        args = self.handler.args
        args.nix_hash = "nix-hash"
        args.group_renderer = "group-renderer"
        args.nix_store = "nix-store"
        invocation = {"id": "import-owner", "revision": "first", "input": {
            "services": {"dbus": {}}, "groups": [],
            "serviceRecipients": {"dbus": "service-owner"}, "groupRecipients": {},
        }}
        handler = bootstrap.Bootstrap(invocation, Rendered, args)
        predicted = "/nix/store/00000000000000000000000000000000-systemd-bootstrap"

        def command(*arguments, input=None):
            if "--print-fixed-path" in arguments:
                return predicted
            if "--add-fixed" in arguments:
                pins = list(handler.roots.iterdir())
                self.assertEqual(len(pins), 1)
                self.assertEqual(os.readlink(pins[0]), predicted)
                self.assertIn(predicted, json.loads(handler.path.read_text())["roots"])
                return predicted
            return "test-hash"

        handler.command = command
        root, _, _ = handler.render()

        self.assertEqual(root, predicted)

        # A failure before alias publication still has durable root custody.
        # Retirement must release the pin without acquiring foreign definitions.
        handler.units.mkdir()
        foreign = handler.units / "dbus.service"
        foreign.write_text("foreign")
        with self.assertRaises(ValueError):
            handler.apply()

        handler.remove()

        self.assertEqual(foreign.read_text(), "foreign")
        self.assertEqual(list(handler.roots.iterdir()), [])
        self.assertFalse(handler.path.exists())

        def failed_import(*arguments, input=None):
            if "--add-fixed" in arguments:
                raise RuntimeError("injected importer failure")
            return command(*arguments, input=input)

        handler.command = failed_import
        handler.receipt = None
        with self.assertRaises(RuntimeError):
            handler.render()

        self.assertIn(predicted, json.loads(handler.path.read_text())["roots"])
        self.assertEqual(handler.observe()["status"], "retry-safe")
        handler.remove()

        self.assertEqual(foreign.read_text(), "foreign")
        self.assertEqual(list(handler.roots.iterdir()), [])

    def test_symlink_parent_cannot_redirect_publication(self):
        outside = self.root / "outside"
        outside.mkdir()
        self.handler.units.symlink_to(outside)

        with self.assertRaises(ValueError):
            self.handler.apply()

        self.assertEqual(list(outside.iterdir()), [])


if __name__ == "__main__":
    unittest.main()
