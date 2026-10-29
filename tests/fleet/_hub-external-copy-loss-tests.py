"""Check identity and retained-envelope substitutions at the called loss boundary."""

import base64
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import unittest


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    loaded = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(loaded)
    return loaded


setup = module("loss_setup", "_hub-external-copy-loss-setup.py")
loss = module("loss_caller", "_hub-external-copy-loss.py")


class LossReadinessTests(unittest.TestCase):
    def setUp(self):
        argv, environment = b"node\0listener\0--config\0private\0", b"NODE_EXTRA_CA_CERTS=selected\0"
        self.process = {"pid": 101, "startTicks": "202", "ownerUid": 0, "executableSha256": "a" * 64,
            "commandLineSha256": hashlib.sha256(argv).hexdigest(), "commandLineBytes": str(len(argv)),
            "environmentSha256": hashlib.sha256(environment).hexdigest()}
        self.installation = {"root": "/private/copy-closed-loss", "configurationSha256": "b" * 64,
            "listenerSourceSha256": "c" * 64}
        self.ready = {"version": 1, "scope": "copy_closed_reply_loss_listener", "pid": 101,
            "startTicks": "202", "ownerUid": 0, "executableSha256": "a" * 64,
            "configurationSha256": "b" * 64, "listenerSourceSha256": "c" * 64,
            "listenAddress": "127.0.0.1:4678", "upstreamAddress": "127.0.0.1:4675",
            "upstreamScheme": "https", "tlsServerName": "localhost",
            "controlSocket": "/private/copy-closed-loss/control.sock",
            "bodyBytesMaximum": "65536", "attemptsMaximum": 64,
            "commandLine": base64.b64encode(argv).decode(), "environment": base64.b64encode(environment).decode()}

    def test_exact_child_and_strict_tls_readiness(self):
        self.assertIs(setup.validate_external_copy_loss_ready(self.ready, self.installation, self.process), self.ready)

    def test_other_lifetime_source_plaintext_or_inputs_refuse(self):
        for field, value in (("pid", 102), ("startTicks", "203"), ("ownerUid", 1),
                ("configurationSha256", "d" * 64), ("upstreamScheme", "http"), ("tlsServerName", None),
                ("commandLine", base64.b64encode(b"other").decode()), ("environment", "invalid!")):
            with self.subTest(field=field), self.assertRaises(ValueError):
                setup.validate_external_copy_loss_ready({**self.ready, field: value}, self.installation, self.process)


class LostEnvelopeTests(unittest.TestCase):
    def setUp(self):
        self.run, self.fingerprint, self.source, self.codec = "1" * 32, "2" * 64, "3" * 64, "4" * 64
        original = {"topology": {"operation_id": "actual-operation"}}
        self.selected = {"originalSha256": self.fingerprint, "sourceDigest": self.source,
            "request": {"original": original}}
        refs = {name: {"file": "/private/attempt-001-" + name, "sha256": str(index) * 64, "byteSize": "100"}
            for index, name in enumerate(("request", "reply", "selection", "verification"), 5)}
        observation = {**refs, "captureId": self.run, "originalSha256": self.fingerprint,
            "loss": {"file": "/private/attempt-001-loss", "sha256": "a" * 64, "byteSize": "100"}}
        self.state = {"terminal": "authenticated_closed_downstream_destroyed", "consumed": True,
            "observation": observation}
        verification = {"version": 1, "scope": "authenticated_copy_closed_envelope_only", "phase": "closed",
            "sourceDigest": self.source, "codecSourceSha256": self.codec, "originalSha256": self.fingerprint,
            "requestSha256": refs["request"]["sha256"], "requestBytes": "100",
            "replySha256": refs["reply"]["sha256"], "replyBytes": "100"}
        self.retained = {"request": json.dumps({"control": "advance", "original": original}).encode(),
            "verification": json.dumps(verification).encode(), "loss": json.dumps({**refs,
                "captureId": self.run, "originalSha256": self.fingerprint, "downstreamDestroyInvoked": True}).encode()}
        self.tools = {"storageCodecSourceSha256": self.codec}

    def test_complete_local_loss_join_keeps_actual_original(self):
        result = loss.validate_external_copy_loss_observation(self.state, self.retained, self.selected, self.tools, self.run)
        self.assertEqual(result["originalSha256"], self.fingerprint)

    def test_request_only_scope_other_original_partial_or_refused_loss_refuse(self):
        cases = []
        for field, value in (("scope", "intrinsic_unauthenticated_pending_copy_request"),
                ("originalSha256", "b" * 64), ("codecSourceSha256", "b" * 64), ("replyBytes", "99")):
            retained = copy.deepcopy(self.retained)
            record = json.loads(retained["verification"]); record[field] = value
            retained["verification"] = json.dumps(record).encode()
            cases.append((self.state, retained))
        state = copy.deepcopy(self.state); state["terminal"] = "unknown_downstream_already_closed"
        cases.append((state, self.retained))
        for state, retained in cases:
            with self.subTest(state=state["terminal"]), self.assertRaises(ValueError):
                loss.validate_external_copy_loss_observation(state, retained, self.selected, self.tools, self.run)


if __name__ == "__main__":
    unittest.main()
