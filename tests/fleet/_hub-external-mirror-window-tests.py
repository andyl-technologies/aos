"""Controlled public Mirror caller cases; no actual provider or VM qualification."""

import copy
import hashlib
import importlib.util
from pathlib import Path
import unittest


spec = importlib.util.spec_from_file_location("mirror_window", Path(__file__).with_name("_hub-external-mirror-window.py"))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def fixture(mode="full"):
    run = "a" * 32
    suffix = "full" if mode == "full" else "pull-through"
    registry = {"registry": {"slug": "external-aaa/mirror-" + suffix,
        "stableId": "registry-" + suffix, "trustKeys": ["controlled:Ed25519:key"]},
        "placement": {"name": "mirror-" + suffix, "bindingName": "external-binding", "resourceVersion": "5",
            "prefix": ".aos-mirror-qualification/" + run + "/final/" + suffix}}
    binding = {"stableId": "external-binding", "resourceVersion": "6", "spec": {"name": "external-binding"}}
    selected = module.mirror_selection(registry, "https://aos.andyl.org:4778/fleet-mirror/" + run,
        run, mode, frontier="1.0.0", source_commit="b" * 64, binding=binding)
    configured = {"registryId": "1", "resourceVersion": "2", **module.mirror_desired(selected),
        "state": "pending", "observedCommit": "", "lastSyncAt": "0", "error": ""}
    paths = ("HEAD", "info/refs") if mode == "full" else (
        "a" * 32 + ".narinfo", "nar/" + "a" * 32 + "-hub-helper.nar.zst")
    source = [{"path": path, "sha256": hashlib.sha256(path.encode()).hexdigest(), "byteSize": len(path)}
        for path in paths]
    value = {"registry": {"id": 1, "slug": selected["registrySlug"], "stable_id": selected["registryStableId"]},
        "mirror": {"registry_id": 1, "resource_version": 2, "upstream_url": selected["upstream"],
            "mode": "full" if mode == "full" else "pullthrough", "verify": 1,
            "refspec": "refs/*", "auth_secret_ref": "", "schedule_secs": 60 if mode == "full" else 0,
            "last_sync_status": "ok", "upstream_frontier": "1.0.0"},
        "placement": {"id": 3, "registry_id": 1, "name": selected["placementName"],
            "prefix": selected["placementPrefix"], "binding_id": 4, "resource_version": 5, "write_spec_version": 1},
        "binding": {"id": 4, "stable_id": selected["bindingStableId"], "resource_version": 6},
        "authority": {"registry_id": 1, "reconciliation_state": "ready", "desired_placement_id": 3,
            "observed_placement_id": 3, "desired_write_spec_version": 1, "observed_write_spec_version": 1,
            "observed_generation": 7, "desired_generation": 7, "observed_binding_write_revision": 8,
            "desired_binding_write_revision": 8},
        "objects": [{"path": row["path"], "digest": "sha256:" + row["sha256"], "size": row["byteSize"],
            "resource_version": 1, "presence": "present", "placement_id": 3,
            "observed_hash": row["sha256"], "observed_size": row["byteSize"], "catalog_object_resource_version": 1}
            for row in source], "imports": [],
        "publication": {"state": "ready", "default_commit": selected["sourceCommit"], "registry_id": 1}}
    visible = [{"path": row["path"], "httpStatus": 200, "sha256": row["sha256"],
        "byteSize": row["byteSize"], "privateCapture": {"controlledReference": row["path"]}}
        for row in source]
    return selected, configured, source, {"value": value, "receipt": {"controlledReference": "sql"}}, visible


class Controls:
    def __init__(self, configured, *, completed=True):
        self.configured = copy.deepcopy(configured)
        self.completed = completed
        self.calls = []

    def reviewed(self, service, plan, apply, request, label):
        self.calls.append((service, plan, apply, copy.deepcopy(request), label))
        if apply == "SetRegistryMirror":
            return {"mirror": copy.deepcopy(self.configured)}
        return {"operation": {"operationId": "mirror-sync:" + "c" * 32,
            "kind": "registry_mirror_sync", "state": "queued"}}

    def call(self, service, method, request):
        self.calls.append((service, method, copy.deepcopy(request)))
        if method == "GetRegistry":
            suffix = "full" if self.configured["mode"] == 1 else "pull-through"
            return {"registry": {"stableId": "registry-" + suffix, "trustKeys": ["controlled:Ed25519:key"]}}
        current = copy.deepcopy(self.configured)
        if self.completed:
            current.update(state="ready", observedCommit="1.0.0", lastSyncAt="99")
        return {"mirror": current}


def baseline(observed):
    initial = copy.deepcopy(observed)
    initial["value"].update(objects=[], imports=[], publication=None)
    return initial


class MirrorWindowTests(unittest.TestCase):
    def test_actual_plan_apply_get_and_sync_keep_acknowledgement_separate(self):
        selected, configured, _, _, _ = fixture()
        controls = Controls(configured)
        current = module.configure_external_mirror(controls, selected, "controlled-mirror")
        acknowledged = module.enqueue_external_mirror_sync(controls, selected, current, "controlled-mirror")
        self.assertEqual(acknowledged["operation"]["state"], "queued")
        self.assertIn("completion unknown", acknowledged["scope"])
        self.assertEqual(controls.calls[0][:3], (module.MIRROR_SERVICE, "PlanSetRegistryMirror", "SetRegistryMirror"))
        self.assertEqual(controls.calls[0][3]["desired"]["signaturePolicy"], "required")
        self.assertEqual(controls.calls[2][:3], (module.MIRROR_SERVICE, "PlanSyncRegistryMirror", "SyncRegistryMirror"))
        self.assertEqual(controls.calls[2][3]["expectedResourceVersion"], "2")

    def test_source_mode_trust_or_version_drift_refuses(self):
        selected, configured, _, _, _ = fixture()
        for field, changed in (("sourceUrl", "https://aos.andyl.org:4778/other"),
                ("refspec", "refs/heads/*"), ("signaturePolicy", "allow_unsigned"),
                ("authSecretRef", "another"), ("mode", 2), ("resourceVersion", "3"),
                ("intervalSeconds", "1")):
            drifted = {**configured, field: changed}
            with self.assertRaises(ValueError):
                module.require_mirror_configuration(drifted, selected, "2")

    def test_same_namespace_cannot_be_used_for_both_modes(self):
        selected, _, _, _, _ = fixture()
        registry = {"registry": {"slug": selected["registrySlug"], "stableId": selected["registryStableId"],
            "trustKeys": ["controlled"]}, "placement": {"name": selected["placementName"],
            "bindingName": "external-binding", "resourceVersion": "5", "prefix": selected["placementPrefix"]}}
        with self.assertRaises(ValueError):
            module.mirror_selection(registry, selected["upstream"], selected["runId"], "pull_through",
                frontier=selected["frontier"], source_commit=selected["sourceCommit"],
                binding={"stableId": "external-binding", "resourceVersion": "6", "spec": {"name": "external-binding"}})

    def test_ready_frontier_does_not_replace_exact_git_commit_and_presence(self):
        selected, configured, source, observed, _ = fixture()
        result = module.require_mirror_effects(observed, selected, configured, source, full=True)
        self.assertEqual(result["objectCount"], 2)
        wrong_commit = copy.deepcopy(observed)
        wrong_commit["value"]["publication"]["default_commit"] = selected["frontier"]
        self.assertIsNone(module.require_mirror_effects(wrong_commit, selected, configured, source, full=True))
        for section, field, changed in (("binding", "stable_id", "another"),
                ("placement", "prefix", ".aos-mirror-qualification/other/final"),
                ("mirror", "resource_version", 3)):
            drifted = copy.deepcopy(observed)
            drifted["value"][section][field] = changed
            with self.assertRaises(ValueError):
                module.require_mirror_effects(drifted, selected, configured, source, full=True)
        drifted = copy.deepcopy(observed)
        drifted["value"]["objects"][0]["catalog_object_resource_version"] = 2
        with self.assertRaises(ValueError):
            module.require_mirror_effects(drifted, selected, configured, source, full=True)

    def test_incomplete_catalogue_or_unsettled_import_never_completes(self):
        selected, configured, source, observed, _ = fixture()
        observed["value"]["objects"].pop()
        self.assertIsNone(module.require_mirror_effects(observed, selected, configured, source, full=True))
        _, _, _, observed, _ = fixture()
        observed["value"]["imports"] = [{"source_path": "HEAD", "state": "published", "commit_digest": None}]
        self.assertIsNone(module.require_mirror_effects(observed, selected, configured, source, full=True))

    def test_queued_operation_does_not_complete_even_with_retained_catalogue(self):
        selected, configured, source, observed, visible = fixture()
        controls = Controls(configured, completed=False)
        ticks, retained = [0], []
        def sleep(seconds):
            ticks[0] += seconds
        with self.assertRaises(RuntimeError):
            module.run_external_mirror_case(controls, selected, source,
                {"backgroundControllers": {"mirrorSync": {"intervalSeconds": 60, "mode": "full"}}},
                install_purpose=lambda *args: {"controlledReference": "purpose"},
                observe_effects=lambda *args: baseline(observed) if args[-1] == 0 else observed,
                read_visible=lambda *args: self.fail("Queued full Mirror must not issue a completion read"),
                retain=lambda name, body: retained.append((name, body)),
                cutoff=2, clock=lambda: ticks[0], sleep=sleep)
        self.assertIsNone(retained[-1][1]["completion"])
        self.assertEqual(retained[-1][1]["queuedAcknowledgement"]["operation"]["state"], "queued")

    def test_full_positive_requires_actual_effects_and_all_visible_source_bytes(self):
        selected, configured, source, observed, visible = fixture()
        calls = []
        def producer(*args):
            calls.append("purpose")
            return {"controlledReference": "purpose"}
        def sql(*args):
            calls.append("sql")
            return baseline(observed) if args[-1] == 0 else observed
        def read(*args):
            calls.append("read")
            return visible
        result = module.run_external_mirror_case(Controls(configured), selected, source,
            {"backgroundControllers": {"mirrorSync": {"intervalSeconds": 60, "mode": "full"}}},
            install_purpose=producer, observe_effects=sql, read_visible=read,
            retain=lambda *args: None, cutoff=10, clock=lambda: 0)
        self.assertEqual(calls, ["sql", "purpose", "sql", "read"])
        self.assertEqual(result["queuedAcknowledgement"]["operation"]["state"], "queued")
        self.assertEqual(result["effects"]["objectCount"], 2)

    def test_pull_through_demand_precedes_sql_and_never_enqueues_sync(self):
        selected, configured, source, observed, visible = fixture("pull_through")
        controls, calls = Controls(configured), []
        def read(*args):
            calls.append("read")
            return visible
        def sql(*args):
            if args[-1] == 0:
                self.assertEqual(calls, [])
                return baseline(observed)
            self.assertEqual(calls, ["read"])
            return observed
        result = module.run_external_mirror_case(controls, selected, source,
            {"backgroundControllers": {"mirrorSync": {"intervalSeconds": 60, "mode": "full"}}},
            install_purpose=lambda *args: {"controlledReference": "purpose"},
            observe_effects=sql, read_visible=read, retain=lambda *args: None,
            cutoff=10, clock=lambda: 0)
        self.assertIsNone(result["queuedAcknowledgement"])
        self.assertFalse(any("SyncRegistryMirror" in call for call in controls.calls))

    def test_existing_destination_effects_refuse_before_functional_admission(self):
        selected, configured, source, observed, visible = fixture()
        with self.assertRaises(ValueError):
            module.run_external_mirror_case(Controls(configured), selected, source,
                {"backgroundControllers": {"mirrorSync": {"intervalSeconds": 60, "mode": "full"}}},
                install_purpose=lambda *args: self.fail("Existing effects must not gain functional admission"),
                observe_effects=lambda *args: observed, read_visible=lambda *args: visible,
                retain=lambda *args: None, cutoff=10, clock=lambda: 0)

    def test_missing_producer_or_expired_original_cutoff_refuses_before_controls(self):
        selected, configured, source, observed, visible = fixture()
        for producer, cutoff in ((None, 10), (lambda *args: {}, 0)):
            controls = Controls(configured)
            with self.assertRaises(ValueError):
                module.run_external_mirror_case(controls, selected, source,
                    {"backgroundControllers": {"mirrorSync": {"intervalSeconds": 60, "mode": "full"}}},
                    install_purpose=producer, observe_effects=lambda *args: observed,
                    read_visible=lambda *args: visible, retain=lambda *args: None,
                    cutoff=cutoff, clock=lambda: 0)
            self.assertEqual(controls.calls, [])

    def test_public_wrong_hash_missing_body_and_unknown_source_refuse(self):
        _, _, source, _, visible = fixture()
        expected = module.require_mirror_source_inventory(source)
        for field, value in (("httpStatus", 503), ("sha256", "d" * 64),
                ("privateCapture", None), ("byteSize", 999), ("path", "unselected")):
            drifted = copy.deepcopy(visible)
            drifted[0][field] = value
            with self.assertRaises(ValueError):
                module.require_mirror_visible_bytes(drifted, expected)

    def test_sql_is_bounded_readonly_and_never_mutates_or_seeds_state(self):
        selected, configured, _, _, _ = fixture()
        queries = []
        module.observe_mirror_effects(lambda query, label: queries.append((query, label)),
            selected, configured, "controlled-current-mirror")
        query = queries[0][0]
        self.assertTrue(query.startswith("BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY;"))
        self.assertTrue(query.endswith("COMMIT;"))
        self.assertIn("JOIN mirror_sources m ON m.registry_id=r.id", query)
        self.assertIn("s.lifecycle_state='active'", query)
        self.assertNotIn("original_json", query)
        self.assertNotIn("progress_json", query)
        self.assertNotIn("UPDATE ", query)
        self.assertNotIn("INSERT ", query)


if __name__ == "__main__":
    unittest.main()
