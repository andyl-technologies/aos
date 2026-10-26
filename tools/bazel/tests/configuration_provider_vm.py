"""Checks installed configuration effects and companion NSS tools in a private VM."""

import copy
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys


def request(path, identity, content="first"):
    """Constructs the provider's resolved configuration-file invocation."""
    return {
        "id": identity, "revision": "revision-one", "action": "apply",
        "effect": {"identity": ["qualification", "configuration", "file", identity]},
        "input": {"path": str(path), "content": content, "mode": "0640",
                  "owner": "12345", "group": "12345"},
    }


def call(binary, state, action, document, environment, reject=False):
    """Executes one process invocation without a shell or PATH lookup."""
    document = copy.deepcopy(document)
    document["action"] = "remove" if action == "remove" else "apply"
    result = subprocess.run(
        [str(binary), "--state-directory", str(state), action],
        input=json.dumps(document).encode(), capture_output=True, env=environment, timeout=15,
    )
    if reject:
        assert result.returncode == 1 and not result.stdout
        assert result.stderr.startswith(b"native configuration handler:")
        return None
    if result.returncode or result.stderr:
        raise ValueError("configuration process failed: " + result.stderr.decode())
    return json.loads(result.stdout)


def main():
    package = Path(sys.argv[1])
    assert os.getuid() == 0, "configuration effects require their isolated root VM"
    root = Path("/var/lib/rfc-0028-configuration-qualification")
    root.mkdir(parents=True)
    state = root / "state"
    binary = package / "bin/aos-configuration-provider"
    helper = package / "bin/aos-account-lookup"
    environment = {
        **os.environ, "PATH": "/no-search-path",
        "AOS_ACCOUNT_LOOKUP": "/no-ambient-account-helper",
        "AOS_TEST_ACCOUNT_LOOKUP": "/no-test-account-helper-in-production",
    }
    completed = []

    # Numeric names deliberately resolve to different numeric identities.
    for name, record in [
        ("passwd", "12345:x:4242:4343:qualification:/nonexistent:/nonexistent\n"),
        ("group", "12345:x:4343:\n"),
    ]:
        path = Path("/etc") / name
        contents = path.read_text()
        assert not any(line.startswith("12345:") for line in contents.splitlines())
        path.write_text(contents.rstrip("\n") + "\n" + record)
        expected = "4242\n" if name == "passwd" else "4343\n"
        result = subprocess.run([str(helper), name, "12345"], capture_output=True, text=True, env=environment, timeout=15)
        assert result.returncode == 0 and result.stdout == expected and not result.stderr
        result = subprocess.run([str(helper), name, "missing-qualification-name"], capture_output=True, env=environment, timeout=15)
        assert result.returncode == 2 and not result.stdout
    completed.append("native-nss-exact-numeric-names-and-absence")

    path = Path("/etc/rfc-0028-configuration-qualification")
    document = request(path, "file")
    result = call(binary, state, "apply", document, environment)
    assert result["path"] == str(path) and path.read_text() == "first"
    metadata = path.stat()
    assert (metadata.st_uid, metadata.st_gid) == (4242, 4343)
    assert stat.S_IMODE(metadata.st_mode) == 0o640
    assert call(binary, state, "observe", document, environment)["status"] == "current"
    completed.append("installed-companion-resolves-ownership-with-ambient-paths-disabled")

    document["input"]["content"] = "second"
    document["revision"] = "revision-two"
    assert call(binary, state, "observe", document, environment)["status"] == "retry-safe"
    call(binary, state, "apply", document, environment)
    assert path.read_text() == "second"
    path.chmod(0o600)
    assert call(binary, state, "observe", document, environment)["status"] == "retry-safe"
    call(binary, state, "apply", document, environment)
    assert stat.S_IMODE(path.stat().st_mode) == 0o640
    completed.append("owned-content-and-metadata-update")

    path.write_text("foreign edit")
    assert call(binary, state, "observe", document, environment)["status"] == "indeterminate"
    call(binary, state, "apply", document, environment, reject=True)
    call(binary, state, "remove", document, environment, reject=True)
    assert path.read_text() == "foreign edit"
    path.write_text("second")
    completed.append("foreign-edits-reject-overwrite-and-removal")

    structured = Path("/etc/rfc-0028-structured-qualification")
    encoded = request(structured, "structured")
    encoded["input"].pop("content")
    encoded["input"].update(format="json", value={"name": "qualification", "values": [1, 2]})
    call(binary, state, "apply", encoded, environment)
    assert json.loads(structured.read_text()) == encoded["input"]["value"]
    assert call(binary, state, "observe", encoded, environment)["status"] == "current"
    call(binary, state, "remove", encoded, environment)
    assert not structured.exists()
    completed.append("structured-json-installation-and-release")

    call(binary, state, "remove", document, environment)
    assert not path.exists()
    call(binary, state, "remove", document, environment)
    completed.append("owned-file-release-is-idempotent")

    private_bin = root / "private-bin"
    private_bin.mkdir()
    relocated = private_bin / binary.name
    shutil.copy2(binary, relocated)
    decoys = root / "path-decoys"
    decoys.mkdir()
    (decoys / helper.name).symlink_to(helper)
    environment["PATH"] = str(decoys)
    missing = Path("/etc/rfc-0028-missing-helper-qualification")
    document = request(missing, "missing-helper")
    call(relocated, state, "apply", document, environment, reject=True)
    assert not missing.exists()
    shutil.copy2(helper, private_bin / helper.name)
    call(relocated, state, "apply", document, environment)
    assert (missing.stat().st_uid, missing.stat().st_gid) == (4242, 4343)
    call(relocated, state, "remove", document, environment)
    assert not missing.exists()
    completed.append("missing-companion-fails-closed-and-adjacent-relocation-works")

    shutil.rmtree(root)
    print("CONFIGURATION_PROVIDER_REPORT:" + json.dumps({"status": "PASS", "cases": completed}, sort_keys=True))


if __name__ == "__main__":
    main()
