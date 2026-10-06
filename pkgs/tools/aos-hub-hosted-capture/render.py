"""Render private capture assets/binding metadata; never read secrets or deploy.

The caller supplies independently selected policy and the actual already-created
shared namespace ID. This renderer does not create an identity or replace the
application's existing environment, Durable Object exports, queues or bindings.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys


ROOT = Path(__file__).parent
ASSETS = ("capture.mjs", "sink.mjs", "baseline-proxy.mjs", "origin-capture.mjs", "storage-shim.mjs")


def selected_node(reference):
    """Resolve the explicitly pinned immutable Node executable without fallback."""
    if (not isinstance(reference, dict) or set(reference) != {"file", "sha256"}
            or not isinstance(reference["file"], str)
            or not isinstance(reference["sha256"], str)
            or re.fullmatch(r"[0-9a-f]{64}", reference["sha256"]) is None):
        raise ValueError("closed immutable Node reference is required")
    path = Path(reference["file"])
    if (not path.is_absolute() or ".." in path.parts
            or re.fullmatch(r"/nix/store/[0-9a-z]{32}-nodejs-[^/]+/bin/node", str(path)) is None):
        raise ValueError("selected immutable Node path is required")
    try:
        resolved = path.resolve(strict=True)
        metadata = resolved.stat()
    except OSError as error:
        raise ValueError("selected Node is unavailable") from error
    if (str(path) != reference["file"] or resolved != path
            or not stat.S_ISREG(metadata.st_mode) or metadata.st_mode & 0o222
            or not os.access(path, os.X_OK)):
        raise ValueError("selected Node custody refused")

    digest = hashlib.sha256()
    with path.open("rb") as executable:
        for chunk in iter(lambda: executable.read(1024 * 1024), b""):
            digest.update(chunk)
    if digest.hexdigest() != reference["sha256"]:
        raise ValueError("selected Node commitment differs")
    return str(path)


def implementation_digest():
    digest = hashlib.sha256()
    for name in ASSETS:
        body = (ROOT / name).read_bytes()
        digest.update(name.encode() + b"\0" + str(len(body)).encode() + b"\0" + body)
    return digest.hexdigest()


def render(stage, policy, namespace_id, bucket_name, ledger_owner_script, *, node_tool):
    """Stage assets and additive provider metadata from an explicit closed policy."""
    if not isinstance(namespace_id, str) or re.fullmatch(r"[0-9a-f]{32}", namespace_id) is None:
        raise ValueError("actual shared capture namespace is required")
    if not isinstance(bucket_name, str) or re.fullmatch(r"[a-z0-9][a-z0-9-]{1,61}[a-z0-9]", bucket_name) is None:
        raise ValueError("actual private capture bucket is required")
    if (not isinstance(ledger_owner_script, str)
            or re.fullmatch(r"[a-z0-9][a-z0-9-]{0,62}", ledger_owner_script) is None):
        raise ValueError("actual capture namespace owner script is required")
    node = selected_node(node_tool)

    # Use the runtime validator itself: rendering must not relax its route,
    # window, source identity, query or body-limit contract.
    validation = subprocess.run(
        [node, "--input-type=module", "-e",
         'import { checkedCapturePolicy } from ' + json.dumps((ROOT / "capture.mjs").as_uri()) + ';'
         'let input="";for await (const chunk of process.stdin) input+=chunk;'
         'try { checkedCapturePolicy(JSON.parse(input)); } catch { process.exit(1); }'],
        input=json.dumps(policy), text=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        timeout=10, check=False)
    if validation.returncode != 0:
        raise ValueError("runtime capture policy refused")
    fields = {"version", "corpusId", "windowId", "sourceCommit", "sourceTree", "runtimeSourceDigest",
              "nativeExecutableSha256", "workerSourceDigest", "captureImplementationSha256",
              "startsAt", "expiresAt", "capturePrefix", "storageOrigin", "originProxyOrigin",
              "originRoutes", "maximumBodyBytes", "maximumCorpusBytes"}
    if set(policy) != fields or policy["captureImplementationSha256"] != implementation_digest():
        raise ValueError("closed measured capture implementation is required")
    if (policy["maximumBodyBytes"] != 8 * 1024 * 1024
            or policy["maximumCorpusBytes"] != 512 * 1024 * 1024):
        raise ValueError("original capture ceilings are required")
    stage = Path(stage)
    stage.mkdir(mode=0o700, exist_ok=False)
    stage.chmod(0o700)
    for name in ASSETS:
        shutil.copyfile(ROOT / name, stage / name)
        (stage / name).chmod(0o600)
    encoded = json.dumps(policy, separators=(",", ":"))
    (stage / "capture-policy.mjs").write_text("export const capturePolicy = " + encoded + ";\n")
    (stage / "capture-bindings.json").write_text(json.dumps({
        "additiveBindingsOnly": True,
        "bindings": [
            {"type": "durable_object_namespace", "name": "PRIVATE_CAPTURE_LEDGER", "namespace_id": namespace_id},
            {"type": "plain_text", "name": "PRIVATE_CAPTURE_POLICY", "text": encoded},
            {"type": "r2_bucket", "name": "PRIVATE_CAPTURE_BUCKET", "bucket_name": bucket_name},
        ],
        "budgetObjectName": policy["corpusId"],
        "privateBucketBindingRequired": "PRIVATE_CAPTURE_BUCKET",
        "captureNamespaceClass": "PrivateCaptureLedger",
        "sharedNamespaceOwner": {
            "scriptName": ledger_owner_script,
            "className": "PrivateCaptureLedger",
            "namespaceId": namespace_id,
            "entryModule": "origin-entry.mjs",
            "requiresIndependentProviderVerification": True,
        },
        "namespaceConsumers": {
            "origin-entry.mjs": "owner-script binding to the supplied namespace_id",
            "storage-entry.mjs": "cross-script binding to the SAME supplied namespace_id",
        },
        "storageExportsCaptureLedger": False,
        "existingApplicationBindingsUnchanged": True,
        "runtimeAcceptanceClaim": False,
    }, indent=2) + "\n")
    (stage / "origin-entry.mjs").write_text(
        'import { createCapturedProxy } from "./origin-capture.mjs";\n'
        'import { bindingSink } from "./sink.mjs";\n'
        'import { capturePolicy } from "./capture-policy.mjs";\n'
        'import { configuration } from "./configuration.mjs";\n'
        'export { PrivateCaptureLedger } from "./sink.mjs";\n'
        'export default { fetch(request, env, ctx) {\n'
        '  return createCapturedProxy(configuration, capturePolicy,\n'
        '    bindingSink(env.PRIVATE_CAPTURE_LEDGER, capturePolicy))(request, env, ctx);\n'
        '} };\n')
    (stage / "storage-entry.mjs").write_text(
        'import Application from "./application/shim.mjs";\n'
        'export * from "./application/shim.mjs";\n'
        'import { createCapturedApplication } from "./storage-shim.mjs";\n'
        'import { bindingSink } from "./sink.mjs";\n'
        'import { capturePolicy } from "./capture-policy.mjs";\n'
        'export default class CapturedStorage extends Application {\n'
        '  fetch(request) {\n'
        '    const delegate = selected => super.fetch(selected);\n'
        '    return createCapturedApplication(delegate, capturePolicy,\n'
        '      bindingSink(this.env.PRIVATE_CAPTURE_LEDGER, capturePolicy))(request, this.env, this.ctx);\n'
        '  }\n'
        '}\n')
    for path in stage.iterdir():
        path.chmod(0o600)
    return stage


SELECTION_FIELDS = {
    "version", "stageDirectory", "capturePolicy", "originConfiguration",
    "namespaceId", "bucketName", "ledgerOwnerScript",
}
MAX_SELECTION_BYTES = 64 * 1024


class StagingRefused(ValueError):
    """Carries a fixed category; selected values and exceptions remain private."""


def unique_fields(pairs):
    result = {}
    for name, value in pairs:
        if name in result:
            raise StagingRefused("selection_refused")
        result[name] = value
    return result


def finite_number(_value):
    raise StagingRefused("selection_refused")


def read_selection(path, *, private=True, maximum=MAX_SELECTION_BYTES):
    """Read a bounded held regular file without following a final symlink."""
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(descriptor, "rb") as selected:
        before = os.fstat(selected.fileno())
        if (not stat.S_ISREG(before.st_mode)
                or (private and (before.st_nlink != 1 or before.st_uid != os.getuid()
                                 or stat.S_IMODE(before.st_mode) != 0o600))):
            raise StagingRefused("selection_custody_refused")
        raw = selected.read(maximum + 1)
        if len(raw) > maximum or len(raw) != before.st_size:
            raise StagingRefused("selection_refused")
        selected.seek(0)
        if selected.read(maximum + 1) != raw:
            raise StagingRefused("selection_custody_refused")
        after = os.fstat(selected.fileno())
        identity = lambda value: (value.st_dev, value.st_ino, value.st_size,
                                  value.st_mtime_ns, value.st_ctime_ns)
        if identity(before) != identity(after):
            raise StagingRefused("selection_custody_refused")
    return json.loads(raw, object_pairs_hook=unique_fields, parse_constant=finite_number)


def selected_stage(value):
    if not isinstance(value, str):
        raise StagingRefused("selection_refused")
    path = Path(value)
    if (not path.is_absolute() or ".." in path.parts or str(path) != value
            or path.exists() or path.is_symlink()):
        raise StagingRefused("stage_refused")
    parent = path.parent
    metadata = parent.lstat()
    if (parent.resolve(strict=True) != parent or not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != os.getuid() or stat.S_IMODE(metadata.st_mode) != 0o700):
        raise StagingRefused("stage_refused")
    return path


def validate_origin(configuration, policy, node):
    # Construct the actual proxy to exercise its closed validator without Fetch.
    validation = subprocess.run(
        [node, "--input-type=module", "-e",
         'import { createProxy } from ' + json.dumps((ROOT / "baseline-proxy.mjs").as_uri()) + ';'
         'let input="";for await (const chunk of process.stdin) input+=chunk;'
         'try { createProxy(JSON.parse(input)); } catch { process.exit(1); }'],
        input=json.dumps(configuration), text=True, stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL, timeout=10, check=False)
    if validation.returncode != 0:
        raise StagingRefused("configuration_refused")
    if (configuration["proxyOrigin"] != policy["originProxyOrigin"]
            or configuration["startsAt"] > policy["startsAt"]
            or configuration["expiresAt"] < policy["expiresAt"]):
        raise StagingRefused("configuration_refused")


def stage_selection(selection, node_tool):
    """Stage a closed private selection; no resource or deployment is created."""
    if (type(selection) is not dict or set(selection) != SELECTION_FIELDS
            or type(selection["version"]) is not int or selection["version"] != 1
            or type(selection["capturePolicy"]) is not dict
            or type(selection["originConfiguration"]) is not dict):
        raise StagingRefused("selection_refused")
    stage = selected_stage(selection["stageDirectory"])
    node = selected_node(node_tool)
    validate_origin(selection["originConfiguration"], selection["capturePolicy"], node)
    stage = render(stage, selection["capturePolicy"], selection["namespaceId"],
                   selection["bucketName"], selection["ledgerOwnerScript"], node_tool=node_tool)
    configuration = json.dumps(selection["originConfiguration"], separators=(",", ":"))
    with (stage / "configuration.mjs").open("x") as output:
        os.chmod(output.fileno(), 0o600)
        output.write("export const configuration = " + configuration + ";\n")

    assets = [{"file": name, "sha256": hashlib.sha256((stage / name).read_bytes()).hexdigest(),
               "byteSize": (stage / name).stat().st_size} for name in ASSETS]
    receipt = {
        "version": 1, "state": "staged", "runtimeAcceptanceClaim": False,
        "captureImplementationSha256": implementation_digest(), "runtimeAssets": assets,
        "rendererSha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "nodeTool": node_tool, "runtimeCommitments": "supplied_unverified",
        "requiresIndependentProviderVerification": True,
    }
    with (stage / "staging-receipt.json").open("x") as output:
        os.chmod(output.fileno(), 0o600)
        json.dump(receipt, output, indent=2)
        output.write("\n")
    return receipt


def main(argv=None):
    parser = argparse.ArgumentParser(description="Stage selected private hosted capture files.")
    parser.add_argument("--selection", required=True)
    parser.add_argument("--node-tool-file", required=True)
    arguments = parser.parse_args(argv)
    try:
        selection = read_selection(arguments.selection)
        node_tool = read_selection(arguments.node_tool_file, private=False, maximum=4096)
        receipt = stage_selection(selection, node_tool)
    except StagingRefused as error:
        print(json.dumps({"state": "refused", "category": str(error)}))
        return 1
    except (ValueError, OSError, KeyError, TypeError, RecursionError, subprocess.TimeoutExpired):
        print(json.dumps({"state": "refused", "category": "staging_refused"}))
        return 1
    print(json.dumps({"state": "staged", "runtimeAssetCount": len(ASSETS),
                      "captureImplementationSha256": receipt["captureImplementationSha256"],
                      "runtimeAcceptanceClaim": False}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
