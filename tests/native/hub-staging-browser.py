"""Checks staged-release browser workflows against deterministic Connect responses.

Run against an isolated native Hub with the current console assets and a fixture
account. Real login, browser permissions, routing, and the compiled console run
in Chrome; candidate API responses are intercepted in the browser so incomplete
uploads, revision replacement, publication, and discard are reproducible. Hub
service tests separately verify storage and publication authorization.
"""

import argparse
import base64
import gzip
import hashlib
import importlib.util
import json
from pathlib import Path


HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("hub_settings_browser", HERE / "hub-settings-browser.py")
if SPEC is None or SPEC.loader is None:
    raise SystemExit("cannot load Chrome transport")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def candidate(registry):
    """Builds a valid inventory with package, image, and container artifact labels."""
    inventory = [
        {"path": f"images/sha256/{'a' * 64}/aos.qcow2", "sha256": f"sha256:{'a' * 64}",
         "byte_size": 200, "kind": "image", "media_type": "application/octet-stream"},
        {"path": "nar/example.nar.zst", "sha256": f"sha256:{'b' * 64}",
         "byte_size": 100, "kind": "package", "media_type": "application/zstd"},
        {"path": "nar/oci-layer.nar.zst", "sha256": f"sha256:{'c' * 64}",
         "byte_size": 300, "kind": "container", "media_type": "application/octet-stream"},
    ]
    encoded = json.dumps(inventory, separators=(",", ":")).encode()
    digest = hashlib.sha256(b"aos.registry-stage-inventory/v1\0" + encoded).hexdigest()
    return {
        "schema": "aos.registry-stage/v1", "id": "browser-candidate", "registry": registry,
        "revision": 1, "release_id": "9.0.0", "source_branch": "dplecki/release-9.0.0",
        "commit": "a" * 40, "inventory_digest": f"sha256:{digest}",
        "inventory": inventory, "publication": [], "store_roots": [],
    }


def interception_script(revision):
    """Replaces only staging calls while retaining real session exchange."""
    return """
        (() => {
            const original = window.fetch.bind(window);
            window.__stagePermission = true;
            window.__stageCalls = [];
            window.__stageFixture = {
                registry: REVISION.registry, stageId: REVISION.id,
                revisionJson: JSON.stringify(REVISION), state: 'draft',
                publicationId: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
                totalBytes: '600', uploadedBytes: '500', verifiedBytes: '500',
                missingPaths: ['nar/example.nar.zst'], missingObjectCount: '1', createdAt: '1', updatedAt: '1'
            };
            window.fetch = async (input, init) => {
                const path = new URL(typeof input === 'string' ? input : input.url, location.href).pathname;
                if (path === '/-/auth/session-token') {
                    const response = await original(input, init);
                    const data = await response.clone().json();
                    if (!window.__stagePermission) {
                        data.routePermissions = (data.routePermissions || []).filter(value => value !== 'publish');
                    }
                    return new Response(JSON.stringify(data), {status: response.status, headers: response.headers});
                }
                const method = path.split('/').pop();
                const methods = ['ListStagedReleases', 'GetStagedRelease', 'UpsertStagedRelease',
                                 'FinalizeStagedRelease', 'DiscardStagedRelease', 'GetRegistryPublication'];
                if (!path.startsWith('/aos.hub.v1.PublishService/') || !methods.includes(method)) {
                    return original(input, init);
                }
                const text = init && typeof init.body === 'string' ? init.body : await input.clone().text();
                const request = JSON.parse(text);
                window.__stageCalls.push({method, request});
                let value;
                if (method === 'ListStagedReleases') {
                    const revision = JSON.parse(window.__stageFixture.revisionJson);
                    value = {stages: [{...window.__stageFixture, revisionJson: '', missingPaths: [],
                        revision: String(revision.revision), releaseId: revision.release_id,
                        sourceBranch: revision.source_branch, commit: revision.commit,
                        inventoryDigest: revision.inventory_digest, objectCount: '3'}]};
                }
                else if (method === 'GetRegistryPublication') value = {
                    publicationId: window.__stageFixture.publicationId, registry: REVISION.registry,
                    state: 'preparing', objects: [{objectId: '1', path: 'nar/example.nar.zst',
                    sha256: 'b'.repeat(64), byteSize: '100', kind: 'immutable',
                    mediaType: 'application/zstd', uploadUrl: ''}]
                };
                else {
                    if (method === 'UpsertStagedRelease') {
                        const bytes = Uint8Array.from(atob(request.revisionGzip), character => character.charCodeAt(0));
                        const inflated = new Blob([bytes]).stream().pipeThrough(new DecompressionStream('gzip'));
                        window.__stageFixture.revisionJson = await new Response(inflated).text();
                    } else if (method === 'FinalizeStagedRelease') {
                        window.__stageFixture.state = 'released';
                        window.__stageFixture.releasedVersion = request.releaseId;
                    } else if (method === 'DiscardStagedRelease') {
                        window.__stageFixture.state = 'discarded';
                    }
                    const revision = JSON.parse(window.__stageFixture.revisionJson);
                    Object.assign(window.__stageFixture, {revision: String(revision.revision),
                        releaseId: revision.release_id, sourceBranch: revision.source_branch,
                        commit: revision.commit, inventoryDigest: revision.inventory_digest,
                        objectCount: String(revision.inventory.length)});
                    const compressed = new Blob([window.__stageFixture.revisionJson]).stream()
                        .pipeThrough(new CompressionStream('gzip'));
                    const bytes = new Uint8Array(await new Response(compressed).arrayBuffer());
                    value = {...window.__stageFixture, revisionJson: '',
                        revisionGzip: btoa(String.fromCharCode(...bytes))};
                }
                return new Response(JSON.stringify(value), {status: 200, headers: {'content-type': 'application/json'}});
            };
        })()
    """.replace("REVISION", json.dumps(revision, separators=(",", ":")))


class StagingAudit(MODULE.HubSettingsSmoke):
    """Exercises actionable incomplete, ready, released, and discarded states."""

    def click(self, text):
        expression = """
            (() => {
                const button = Array.from(document.querySelectorAll('button')).find(item => item.textContent.trim() === LABEL);
                if (!button || button.disabled) return false;
                button.click(); return true;
            })()
        """.replace("LABEL", json.dumps(text))
        self.check(self.chrome.evaluate(expression), f"{text} is usable")

    def run_staging(self, registry):
        revision = candidate(registry)
        self.chrome.call("Page.addScriptToEvaluateOnNewDocument", {"source": interception_script(revision)})
        self.login()
        path = f"/{registry}/-/settings/staged-releases"
        self.navigate(path)
        self.wait_for("document.body.textContent.includes('browser-candidate')", "candidate list")
        self.click("Review candidate")
        self.wait_for("document.querySelector('.stage-inventory') !== null", "candidate inventory")
        self.check(self.chrome.evaluate("document.querySelectorAll('.stage-inventory tbody tr').length === 3"),
                   "review shows package, image, and container inventory")
        self.check(self.chrome.evaluate("Array.from(document.querySelectorAll('button')).some(button => button.textContent.trim() === 'Publish reviewed release' && button.disabled)"),
                   "incomplete candidate cannot publish")
        self.check(self.chrome.evaluate("document.body.textContent.includes('apr release 9.0.0 --stage browser-candidate --stage-revision 1 --resume')"),
                   "incomplete candidate provides exact resume command")
        self.screenshot_pair("staged-incomplete")

        next_revision = dict(revision, revision=2, commit="b" * 40)
        self.chrome.evaluate("""
            (() => {
                const details = Array.from(document.querySelectorAll('details')).find(item => item.querySelector('summary')?.textContent.trim() === 'Update candidate revision');
                details.open = true;
                const input = details.querySelector('input[type=file]');
                const files = new DataTransfer();
                files.items.add(new File([CONTENTS], 'candidate.json', {type: 'application/json'}));
                input.files = files.files;
                input.dispatchEvent(new Event('change', {bubbles: true}));
            })()
        """.replace("CONTENTS", json.dumps(json.dumps(next_revision))))
        self.wait_for("Array.from(document.querySelectorAll('button')).some(button => button.textContent.trim() === 'Save reviewed revision' && !button.disabled)", "replacement candidate review")
        self.click("Save reviewed revision")
        self.wait_for("window.__stageCalls.some(call => call.method === 'UpsertStagedRelease')", "revision update")
        update = self.chrome.evaluate("window.__stageCalls.find(call => call.method === 'UpsertStagedRelease').request")
        reviewed = json.loads(gzip.decompress(base64.b64decode(update["revisionGzip"])))
        self.check(str(update["expectedRevision"]) == "1" and reviewed["commit"] == "b" * 40,
                   "revision update preserves compare-and-swap and reviewed exact commit")
        self.chrome.evaluate("window.__stageFixture.state = 'ready'; window.__stageFixture.uploadedBytes = '600'; window.__stageFixture.verifiedBytes = '600'; window.__stageFixture.missingPaths = []; window.__stageFixture.missingObjectCount = '0'")
        self.click("Refresh progress")
        self.wait_for("document.querySelector('.stage-progress')?.value === 100", "verified complete candidate")
        self.check(self.chrome.evaluate("Array.from(document.querySelectorAll('button')).some(button => button.textContent.trim() === 'Publish reviewed release' && button.disabled)"),
                   "complete candidate still requires explicit review confirmation")
        self.chrome.evaluate("document.querySelector('.subworkflow input[type=checkbox]').click()")
        self.click("Publish reviewed release")
        self.wait_for("document.body.textContent.includes('This exact revision is published')", "published result")
        final = self.chrome.evaluate("window.__stageCalls.find(call => call.method === 'FinalizeStagedRelease').request")
        self.check(str(final["expectedRevision"]) == "2" and final["releaseId"] == "9.0.0",
                   "publication freezes the reviewed revision and reserved version")
        self.check(self.chrome.evaluate("Array.from(document.querySelectorAll('a')).some(link => link.textContent.trim() === 'View channel assignments')"),
                   "channels remain a separate action after publication")
        self.screenshot_pair("staged-released")

        self.click("Close review")
        self.chrome.evaluate("""
            (() => {
                const revision = JSON.parse(window.__stageFixture.revisionJson);
                revision.id = 'discard-candidate'; revision.release_id = '9.0.1';
                window.__stageFixture = {...window.__stageFixture, stageId: revision.id,
                    revisionJson: JSON.stringify(revision), state: 'ready', releasedVersion: ''};
            })()
        """)
        self.click("Refresh list")
        self.wait_for("document.querySelector('.loading-row') === null", "refreshed list")
        self.click("Review candidate")
        self.wait_for("document.querySelector('.danger-subworkflow') !== null", "discard controls")
        self.chrome.evaluate("document.querySelector('.danger-subworkflow').open = true")
        self.check(self.chrome.evaluate("Array.from(document.querySelectorAll('button')).some(button => button.textContent.trim() === 'Discard confirmed stage' && button.disabled)"),
                   "discard requires the exact stage identity")
        self.chrome.evaluate("const input = document.querySelector('.danger-subworkflow input'); input.value = 'discard-candidate'; input.dispatchEvent(new Event('input', {bubbles: true}))")
        self.click("Discard confirmed stage")
        self.wait_for("document.body.textContent.includes('This stage was discarded')", "discarded result")
        discarded = self.chrome.evaluate("window.__stageCalls.find(call => call.method === 'DiscardStagedRelease').request")
        self.check(str(discarded["expectedRevision"]) == "2", "discard uses the reviewed revision")

        self.chrome.call("Page.addScriptToEvaluateOnNewDocument", {"source": "window.__stagePermission = false;"})
        self.navigate(path)
        self.wait_for("document.body.textContent.includes('Permission required')", "Publish permission boundary")
        self.check(self.chrome.evaluate("window.__stageCalls.length === 0"),
                   "read access never fetches private staged releases")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--browser", required=True)
    parser.add_argument("--url", required=True)
    parser.add_argument("--email", required=True)
    parser.add_argument("--password-file", required=True)
    parser.add_argument("--registry", default="demo/cdn")
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--timeout", type=float, default=30)
    args = parser.parse_args()
    output = Path(args.output_dir).resolve()
    output.mkdir(parents=True, exist_ok=True)
    password = Path(args.password_file).read_text().rstrip("\r\n")
    chrome = MODULE.ChromePipe(args.browser, output, args.timeout)
    audit = StagingAudit(chrome, args.url, args.email, password, output, args.timeout)
    failure = None
    try:
        chrome.start()
        audit.run_staging(args.registry)
        if chrome.javascript_errors or chrome.console_errors:
            raise AssertionError("browser reported a JavaScript or console error")
    except BaseException as error:
        failure = error
    finally:
        chrome.drain_events()
        (output / "report.json").write_text(json.dumps(audit.report(failure), indent=2) + "\n")
        chrome.close()
    if failure is not None:
        print(f"FAIL {failure}; inspect {output / 'report.json'}", flush=True)
        return 1
    print(f"PASS {len(audit.checks)} staging browser checks; evidence in {output}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
