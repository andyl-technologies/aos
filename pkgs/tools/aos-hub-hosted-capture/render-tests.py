"""Local renderer/subclass tests with an explicitly selected immutable AOS Node.

No provider or deployment access occurs.
"""

import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import time
import unittest

import render


class RendererTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.node_tool = json.loads(os.environ["AOS_CAPTURE_NODE_TOOL"])
        cls.node = render.selected_node(cls.node_tool)

    def policy(self):
        now = int(time.time())
        return {
            "version": 1, "corpusId": "1" * 32, "windowId": "2" * 32,
            "sourceCommit": "3" * 40, "sourceTree": "4" * 40,
            "runtimeSourceDigest": "5" * 64, "nativeExecutableSha256": "6" * 64,
            "workerSourceDigest": "7" * 64,
            "captureImplementationSha256": render.implementation_digest(),
            "startsAt": now - 1, "expiresAt": now + 3599,
            "capturePrefix": "private-capture/" + "1" * 32 + "/",
            "storageOrigin": "https://storage.fixture.test",
            "originProxyOrigin": "https://origin.fixture.test", "originRoutes": [],
            "maximumBodyBytes": 8 * 1024 * 1024, "maximumCorpusBytes": 512 * 1024 * 1024,
        }

    def test_policy_refusal_precedes_stage_creation(self):
        with tempfile.TemporaryDirectory() as parent:
            for change in (
                {"expiresAt": int(time.time()) + 3601},
                {"originRoutes": [{"method": "POST", "path": "/aos.hub.v1.DirectUploadService/GrantPartsBatch", "purpose": "grant"}]},
                {"storageOrigin": "https://storage.fixture.test/?private=unsupported"},
                {"captureImplementationSha256": "0" * 64},
            ):
                stage = Path(parent) / "refused"
                with self.assertRaises(ValueError):
                    render.render(stage, self.policy() | change, "8" * 32,
                                  "private-fixture-corpus", "fixture-capture-owner",
                                  node_tool=self.node_tool)
                self.assertFalse(stage.exists())

    def test_actual_binding_identifiers_required(self):
        with tempfile.TemporaryDirectory() as parent:
            for namespace, bucket in (("", "private-fixture-corpus"), ("8" * 32, "../not-a-bucket")):
                stage = Path(parent) / "refused"
                with self.assertRaises(ValueError):
                    render.render(stage, self.policy(), namespace, bucket,
                                  "fixture-capture-owner", node_tool=self.node_tool)
                self.assertFalse(stage.exists())

        with tempfile.TemporaryDirectory() as parent:
            for tool in ({"file": self.node, "sha256": "0" * 64},
                         {"file": self.node + "/../node", "sha256": self.node_tool["sha256"]},
                         {**self.node_tool, "extra": "unsupported"}):
                stage = Path(parent) / "refused-tool"
                with self.assertRaises(ValueError):
                    render.render(stage, self.policy(), "8" * 32, "private-fixture-corpus",
                                  "fixture-capture-owner", node_tool=tool)
                self.assertFalse(stage.exists())

    def test_owner_mapping_is_required_before_stage_creation(self):
        with tempfile.TemporaryDirectory() as parent:
            for owner in ("", "../not-a-script"):
                stage = Path(parent) / "refused"
                with self.assertRaises(ValueError):
                    render.render(stage, self.policy(), "8" * 32, "private-fixture-corpus",
                                  owner, node_tool=self.node_tool)
                self.assertFalse(stage.exists())

    def test_private_additive_bindings_and_create_only_stage(self):
        with tempfile.TemporaryDirectory() as parent:
            stage = Path(parent) / "rendered"
            render.render(stage, self.policy(), "8" * 32, "private-fixture-corpus",
                          "fixture-capture-owner", node_tool=self.node_tool)
            self.assertEqual(stat.S_IMODE(stage.stat().st_mode), 0o700)
            for path in stage.iterdir():
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            bindings = json.loads((stage / "capture-bindings.json").read_text())
            self.assertTrue(bindings["additiveBindingsOnly"])
            self.assertTrue(bindings["existingApplicationBindingsUnchanged"])
            self.assertFalse(bindings["runtimeAcceptanceClaim"])
            self.assertEqual(bindings["bindings"][0]["namespace_id"], "8" * 32)
            self.assertEqual(bindings["bindings"][2]["bucket_name"], "private-fixture-corpus")
            with self.assertRaises(FileExistsError):
                render.render(stage, self.policy(), "8" * 32, "private-fixture-corpus",
                          "fixture-capture-owner", node_tool=self.node_tool)

    def test_actual_generated_entry_preserves_inheritance_and_once_dispatch(self):
        with tempfile.TemporaryDirectory() as parent:
            stage = render.render(Path(parent) / "rendered", self.policy(), "8" * 32,
                                  "private-fixture-corpus", "fixture-capture-owner",
                                  node_tool=self.node_tool)
            application = stage / "application"
            application.mkdir(mode=0o700)
            (application / "shim.mjs").write_text('''
export class ExistingLedger {}
export default class Application {
  constructor(env, ctx) { this.env = env; this.ctx = ctx; this.calls = 0; }
  async fetch(request) {
    this.calls += 1;
    if (request.url !== "https://storage.fixture.test/_internal/storage/v1/execute") throw new Error("URL changed");
    if (await request.text() !== "{}") throw new Error("body changed");
    return new Response("original", { status: 202 });
  }
  queue(batch) { return batch; }
  scheduled(event) { return event; }
}
''')
            (stage / "configuration.mjs").write_text("export const configuration = null;\n")
            script = '''
import assert from "node:assert/strict";
import Captured, { ExistingLedger } from "./storage-entry.mjs";
import * as consumerExports from "./storage-entry.mjs";
import * as ownerExports from "./origin-entry.mjs";
assert.equal(typeof ownerExports.PrivateCaptureLedger, "function");
assert.equal(Object.hasOwn(consumerExports, "PrivateCaptureLedger"), false);
let posts = 0;
const jobs = [];
const env = { PRIVATE_CAPTURE_LEDGER: {
  idFromName(name) { assert.equal(name, "1".repeat(32)); return name; },
  get() { return { async fetch() { posts += 1; return new Response(null, { status: 204 }); } }; }
} };
const instance = new Captured(env, { waitUntil(job) { jobs.push(job); } });
assert.equal(typeof ExistingLedger, "function");
assert.equal(instance.queue("original-queue"), "original-queue");
assert.equal(instance.scheduled("original-scheduled"), "original-scheduled");
const reply = await instance.fetch(new Request("https://storage.fixture.test/_internal/storage/v1/execute", {
  method: "POST", body: "{}"
}));
assert.equal(reply.status, 202); assert.equal(await reply.text(), "original");
for (let i = 0; i < jobs.length; i++) await jobs[i];
assert.equal(instance.calls, 1); assert.equal(posts, 3);
'''
            result = subprocess.run([self.node, "--input-type=module", "-e", script], cwd=stage,
                                    capture_output=True, timeout=10, check=False)
            self.assertEqual(result.returncode, 0, result.stderr.decode())


if __name__ == "__main__":
    unittest.main()
