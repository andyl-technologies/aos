"""Check that listener readiness cannot borrow another child's custody."""

import copy
import importlib.util
import json
from pathlib import Path
import unittest


specification = importlib.util.spec_from_file_location(
    "provider_setup", Path(__file__).with_name("_hub-direct-provider-hold-setup.py"))
setup = importlib.util.module_from_spec(specification)
specification.loader.exec_module(setup)


class ProviderReadinessTests(unittest.TestCase):
    def setUp(self):
        self.prepared = {"root": "/var/lib/hybrid-s3/read-timeout",
            "configurationSha256": "a" * 64, "listenerSourceSha256": "b" * 64}
        self.process = {"pid": 101, "startTicks": "202", "ownerUid": 0,
            "executableSha256": "c" * 64, "commandLineSha256": "d" * 64,
            "commandLineBytes": "30", "environmentSha256": "e" * 64}
        self.ready = {"version": 1, "scope": "garage_response_hold_listener",
            "pid": 101, "startTicks": "202", "ownerUid": 0,
            "configurationSha256": "a" * 64, "executableSha256": "c" * 64,
            "listenerSourceSha256": "b" * 64,
            "listenAddress": "127.0.0.1:3902", "upstreamAddress": "127.0.0.1:3900",
            "controlSocket": self.prepared["root"] + "/control.sock", "bodyBound": "65536",
            "commandLine": {"path": self.prepared["root"] + "/command-line.private",
                "sha256": "d" * 64, "byteSize": "30"},
            "environment": {"path": self.prepared["root"] + "/environment.private",
                "sha256": "e" * 64, "byteSize": "100"}}

    def validate(self, ready):
        return setup.validate_direct_provider_hold_ready(ready, self.prepared, self.process)

    def test_exact_postbind_record_joins_selected_child(self):
        self.assertIs(self.validate(self.ready), self.ready)

    def test_partial_owner_requires_exact_initial_prefixes_and_distinct_transport(self):
        prefixes = ["/fleet-s3/" + (".aos-direct-qualification/external-oci/" + "1" * 32 + "/") * 2 + "registry/"]
        prepared = {**self.prepared, "root": "/var/lib/hybrid-s3/copy-partial", "partialPrefixes": prefixes}
        ready = copy.deepcopy(self.ready)
        ready.pop("bodyBound")
        ready.update(scope="copy_partial_response_listener", listenAddress="127.0.0.1:3903",
            upstreamAddress="127.0.0.1:3902", controlSocket=prepared["root"] + "/control.sock",
            prefixBytes="65536", bodyBlockBound="65536", selectedPrefixes=prefixes)
        for field, filename in (("commandLine", "command-line.private"), ("environment", "environment.private")):
            ready[field]["path"] = prepared["root"] + "/" + filename
        self.assertIs(setup.validate_direct_provider_hold_ready(ready, prepared, self.process), ready)
        for field, value in (("selectedPrefixes", [prefixes[0].replace("1" * 32, "2" * 32)]),
                ("listenAddress", "127.0.0.1:3902"), ("upstreamAddress", "127.0.0.1:3900"),
                ("prefixBytes", "0"), ("bodyBlockBound", "131072")):
            changed = copy.deepcopy(ready)
            changed[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                setup.validate_direct_provider_hold_ready(changed, prepared, self.process)

    def test_partial_control_refuses_other_case_and_authority_fields_before_dispatch(self):
        prefix = "/fleet-s3/" + (".aos-direct-qualification/external-oci/" + "1" * 32 + "/") * 2 + "registry/"
        installation = {"root": "/var/lib/hybrid-s3/copy-partial", "partialPrefixes": [prefix],
            "ready": {"controlSocket": "/var/lib/hybrid-s3/copy-partial/control.sock"}}
        for request in ({"version": 1, "kind": "state", "targetPrefix": prefix + "other/"},
                {"version": 1, "kind": "arm", "targetPrefix": prefix, "holdUntilUnixMillis": True},
                {"version": 1, "kind": "release", "targetPrefix": prefix, "settled": True},
                {"version": 1, "kind": "delete", "targetPrefix": prefix}):
            with self.subTest(request=request), self.assertRaises(ValueError):
                setup.direct_copy_partial_command(None, {}, installation, request)

    def test_inventory_control_selects_only_exact_blob_and_fixed_continuation(self):
        prefix = "/fleet-s3/" + (".aos-direct-qualification/external-oci/" + "1" * 32 + "/") * 2 + "registry/"
        installation = {"root": "/var/lib/hybrid-s3/copy-partial", "partialPrefixes": [prefix],
            "ready": {"controlSocket": "/var/lib/hybrid-s3/copy-partial/control.sock"}}
        request = {"version": 1, "kind": "arm_inventory", "targetPrefix": prefix,
            "sourceKey": prefix + "oci/blobs/sha256/" + "a" * 64,
            "rangeStart": 8388608, "holdUntilUnixMillis": 10000}
        calls = []
        original = setup._direct_provider_listener_exchange
        setup._direct_provider_listener_exchange = lambda machine, tools, selected, body: calls.append(
            (selected, json.loads(body))) or {"version": 1, "status": "armed"}
        try:
            setup.direct_copy_partial_command(None, {}, installation, request)
            self.assertEqual(calls, [(installation, request)])
            for field, changed in (("rangeStart", 0), ("rangeStart", True),
                    ("sourceKey", prefix + "oci/blobs/sha256/extra/" + "a" * 64),
                    ("sourceKey", request["sourceKey"] + "?credential=private"),
                    ("targetPrefix", prefix.replace("1" * 32, "2" * 32))):
                with self.subTest(field=field), self.assertRaises(ValueError):
                    setup.direct_copy_partial_command(None, {}, installation, {**request, field: changed})
            self.assertEqual(len(calls), 1)
        finally:
            setup._direct_provider_listener_exchange = original

    def test_other_child_lifetime_configuration_or_endpoint_refuses(self):
        for name, value in (("pid", 102), ("startTicks", "203"), ("ownerUid", 1),
                ("configurationSha256", "f" * 64), ("listenerSourceSha256", "f" * 64),
                ("executableSha256", "f" * 64), ("listenAddress", "0.0.0.0:3902"),
                ("upstreamAddress", "127.0.0.1:3901"), ("bodyBound", "4194304")):
            with self.subTest(name=name):
                changed = copy.deepcopy(self.ready)
                changed[name] = value
                with self.assertRaises(ValueError):
                    self.validate(changed)

    def test_closed_record_has_no_authority_or_provider_success_fields(self):
        changed = copy.deepcopy(self.ready)
        changed["accepted"] = True
        with self.assertRaises(ValueError):
            self.validate(changed)
        changed = copy.deepcopy(self.ready)
        del changed["startTicks"]
        with self.assertRaises(ValueError):
            self.validate(changed)

    def test_private_process_reference_cannot_substitute_another_file_or_count(self):
        for name, field, value in (("commandLine", "path", "/tmp/cmdline"),
                ("commandLine", "sha256", "f" * 64), ("commandLine", "byteSize", "31"),
                ("environment", "sha256", "f" * 64), ("environment", "byteSize", "0100"),
                ("environment", "byteSize", "65537")):
            with self.subTest(name=name, field=field):
                changed = copy.deepcopy(self.ready)
                changed[name][field] = value
                with self.assertRaises(ValueError):
                    self.validate(changed)

    def test_control_refuses_unselected_socket_or_extra_effect_fields_before_dispatch(self):
        installation = {**self.prepared, "ready": self.ready, "process": self.process}
        rejected = [({**installation, "root": "/tmp/other"}, {"version": 1, "kind": "state"}),
            (installation, {"version": True, "kind": "state"}),
            (installation, {"version": 1, "kind": "delete"}),
            (installation, {"version": 1, "kind": "state", "accepted": True}),
            (installation, {"version": 1, "kind": "arm", "calibrationSha256": "a" * 64,
                "expectedSourceBodySha256": "b" * 64, "calibrationContextSha256": "c" * 64,
                "holdUntilUnixMillis": True})]
        for selected, request in rejected:
            with self.subTest(request=request), self.assertRaises(ValueError):
                setup.direct_provider_hold_command(None, {}, selected, request)

    def test_first_response_rejects_other_scope_unknown_fields_and_invented_original(self):
        installation = {**self.prepared, "ready": self.ready, "process": self.process}
        original = {"version": 1, "kind": "arm_first_response", "selection": {
            "version": 1, "host": "s3.fleet.test",
            "targetPrefix": "/fleet-s3/.aos-direct-qualification/abc/.aos-direct-upload/"},
            "expectedSourceBodySha256": "a" * 64, "expectedSourceBodyBytes": "128",
            "selectionContextSha256": "b" * 64, "holdUntilUnixMillis": 10000}
        replacements = [("host", "other.test"), ("version", True),
            ("targetPrefix", "/fleet-s3/ordinary/.aos-direct-upload/"),
            ("targetPrefix", "/fleet-s3/.aos-direct-qualification/../.aos-direct-upload/"),
            ("targetPrefix", "/fleet-s3/.aos-direct-qualification/%2e/.aos-direct-upload/")]
        for field, value in replacements:
            changed = copy.deepcopy(original)
            changed["selection"][field] = value
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                setup.direct_provider_hold_command(None, {}, installation, changed)
        for field, value in (("expectedSourceBodyBytes", "0128"),
                ("expectedSourceBodyBytes", "65537"), ("holdUntilUnixMillis", True),
                ("expectedSourceBodySha256", "missing"), ("originalSha256", "c" * 64)):
            changed = copy.deepcopy(original)
            changed[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                setup.direct_provider_hold_command(None, {}, installation, changed)


if __name__ == "__main__":
    unittest.main()
