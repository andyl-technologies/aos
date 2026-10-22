"""Qualifies actual surface-index owner admission with independent Unix roles."""

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time


def require(condition, message):
    """Refuses missing evidence rather than manufacturing native authority."""
    if not condition:
        raise RuntimeError(message)


def verify_surface(image, source):
    """Matches the installed fifth executable to its actual retained Cargo event."""
    identity = json.loads((image / "surface-identity.json").read_text())
    require(identity["source"] == str(source), "surface image source mismatch")
    rows = [json.loads(line) for line in (image / "surface-build.jsonl").read_text().splitlines()]
    artifacts = [row for row in rows if row.get("reason") == "compiler-artifact"
                 and row.get("target", {}).get("name") == "surface_index_owner_fixture"
                 and row.get("executable")]
    require(artifacts == [identity["artifact"]], "surface Cargo artifact mismatch")
    artifact = artifacts[0]
    require(artifact["target"]["kind"] == ["example"]
            and artifact["target"]["crate_types"] == ["bin"]
            and artifact["target"]["src_path"].endswith(
                "/terrane/linux/terrane-linux/examples/surface_index_owner_fixture.rs")
            and artifact["features"] == ["native-test-fixtures", "surface-fuse", "tokio"]
            and artifact["profile"] == {"opt_level": "0", "debuginfo": 2,
                "debug_assertions": True, "overflow_checks": True, "test": False},
            "surface example target, features or profile mismatch")
    executable = image / "libexec/surface-index-owner-fixture"
    require(executable.read_bytes().startswith(b"\x7fELF")
            and hashlib.sha256(executable.read_bytes()).hexdigest() == identity["executable_sha256"],
            "surface installed ELF differs from actual Cargo bytes")
    for relative, digest in identity["input_sha256"].items():
        path = source / relative if relative.startswith("tests/") else source / "crates" / relative
        require(hashlib.sha256(path.read_bytes()).hexdigest() == digest,
                "surface immutable input mismatch: " + relative)
    supervisor = source / "tests/terrane/surface_index_owner_vm.py"
    require(Path(__file__).read_bytes() == supervisor.read_bytes(),
            "installed surface supervisor differs from immutable source")


def main():
    """Runs real provision/query/publisher processes and bounded confined actors."""
    image, source = map(Path, sys.argv[1:])
    require(os.geteuid() == 0, "surface supervisor requires explicit administration")
    spec = importlib.util.spec_from_file_location("native_owner_support", image / "share/host_cache_vm.py")
    require(spec is not None and spec.loader is not None, "native support unavailable")
    support = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = support
    spec.loader.exec_module(support)
    support.verify_image()
    verify_surface(image, source)
    # Use the same real provisioning and checked role launchers with two empty
    # domains. These are fixture inputs, never quota or recovery receipts.
    support.CASES = ["empty", "pin"]
    support.BUDGET = support.HARD * len(support.CASES)
    support.administrative_preflight("before")
    support.scaffold()
    support.administrative_preflight("after")
    quota_config, publisher_config = support.configurations()
    # Explicit host policy enables the new read-only protocol; peers cannot
    # supply traversal paths or increase these descriptor and scan bounds.
    quota_config.write_text(
        "project_census = { retained_inodes = 512, directory_entries = 4096, depth = 16 }\n"
        + quota_config.read_text())
    helper = image / "bin/aos-terrane-host"
    ledger = support.ADMIN / "ledger.toml"
    support.run(support.admin_command(support.PROVISION_CAPS,
                [helper, "provision", "--config", quota_config, "--ledger", ledger]),
                preexec_fn=support.native_descriptor_budget)
    uuid = subprocess.check_output(["blkid", "-s", "UUID", "-o", "value",
        os.environ["TERRANE_CACHE_VM_IMAGE"]], text=True, timeout=5).strip().replace("-", "")
    require(len(uuid) == 32, "actual surface project filesystem UUID unavailable")

    def environment(case):
        return dict(os.environ, TERRANE_CACHE_ROOT=str(support.root(case)),
            TERRANE_CACHE_DOMAIN=support.domain(case), TERRANE_CACHE_OWNER=support.owner(case),
            TERRANE_CACHE_PROJECT=str(support.project(case)), TERRANE_CACHE_UUID=uuid,
            TERRANE_CACHE_BUDGET=str(support.BUDGET),
            TERRANE_CACHE_QUOTA_SOCKET=str(support.RUNTIME / "quota.sock"),
            TERRANE_CACHE_PUBLISHER_SOCKET=str(support.PUB_RUNTIME / "publisher.sock"))

    children, logs = [], []
    try:
        for name in ["helper", "publisher"]:
            logs.append((support.RUNTIME / (name + ".log")).open("wb"))
        query = subprocess.Popen(support.admin_command(support.QUERY_CAPS,
            [helper, "serve", "--config", quota_config, "--ledger", ledger]),
            stdout=logs[0], stderr=subprocess.STDOUT, preexec_fn=support.native_descriptor_budget)
        children.append(query)
        deadline = time.monotonic() + 10
        while True:
            result = subprocess.run([str(helper), "query", "--config", str(quota_config),
                "--owner", support.owner("empty"), "--domain", "public"], capture_output=True, timeout=6)
            if result.returncode == 0:
                break
            require(query.poll() is None and time.monotonic() < deadline,
                    "actual surface quota helper failed readiness")
            time.sleep(0.02)
        publisher = subprocess.Popen(support.role_command(841,
            [image / "bin/terrane", "--config", publisher_config, "--role", "publish"]),
            stdout=logs[1], stderr=subprocess.STDOUT, preexec_fn=support.native_descriptor_budget)
        children.append(publisher)
        executable = image / "bin/surface-index-owner-fixture"

        def actor(case, mode, timeout=30):
            """Preserves actor diagnostics under each explicit finite contract."""
            try:
                result = subprocess.run(support.role_command(840, [executable, mode]),
                    env=environment(case), text=True, capture_output=True, timeout=timeout)
            except subprocess.TimeoutExpired as error:
                # TimeoutExpired retains bytes even when text=True. Publish
                # those captured diagnostics before the unchanged failure.
                for stream in [error.stdout, error.stderr]:
                    if stream:
                        print(stream.decode(errors="replace") if isinstance(stream, bytes)
                              else stream, end="", flush=True)
                raise
            print(result.stdout, end="", flush=True)
            print(result.stderr, end="", flush=True)
            return result

        deadline = time.monotonic() + 15
        while True:
            result = subprocess.run(support.role_command(840, [executable, "prepare"]),
                env=environment("empty"), text=True, capture_output=True, timeout=12)
            if result.returncode == 0:
                require(result.stdout.splitlines() == ["PASS actual surface owner native preparation"],
                        "surface preparation witness missing")
                break
            require(publisher.poll() is None and time.monotonic() < deadline,
                    "actual surface publisher failed preparation: " + result.stderr)
            time.sleep(0.02)
        expected = {
            "run": [
                "PASS surface admission requires actual recovery and acknowledged Resume",
                "PASS cancelled surface waiter retains canonical sealed inode and warm requests share original inode",
                "PASS surface indexes are kernel immutable; warm reuse and invalid nodes cause no durable mutation or content fetch",
                "PASS cold recovery retires index names and copy holds while retaining actual mapped bytes and project charge",
                "PASS cold recompilation creates a distinct inode and final old-index unmap releases exactly its project charge",
                "PASS warm surface eviction refuses retained receipts without effects and releases exact mapped charge only after final unmap",
                "PASS actual signed root admits canonical index; changed policy denies disclosure and foreign domain causes no physical mutation",
                "PASS signed-root mapping retains original sealed cache custody, refuses changed policy before disclosure and blocks warm retirement until drop",
                "PASS mapped signed root scopes actual sealed file backing; another commit is denied before pin effects and changed policy denies disclosure",
            ],
            "cap": [
                "PASS surface admission requires actual recovery and acknowledged Resume",
                "PASS actual separate surface cap retains sealed inode, durable hold and faulted owner",
                "PASS cold recovery retires actual cap-failure index before releasing its copy hold",
            ],
        }
        for case, mode in [("empty", "run"), ("pin", "cap")]:
            result = actor(case, mode)
            require(result.returncode == 0 and result.stdout.splitlines() == expected[mode],
                    "actual surface-owner actor failed: " + mode)
            require(not list((support.root(case) / "chunks").iterdir()),
                    "surface fixture unexpectedly admitted encoded content")
            sealed = support.root(case) / "sealed"
            if mode == "run":
                bodies = list(sealed.glob("*/*"))
                require(len(bodies) == 1 and bodies[0].read_bytes() == b"signed surface source"
                        and bodies[0].parent.name == bodies[0].name[:2]
                        and len(bodies[0].name) == 64
                        and all(char in "0123456789abcdef" for char in bodies[0].name),
                        "scoped file fixture did not retain its exact deliberately published body")
            else:
                require(not list(sealed.iterdir()),
                        "metadata-only cap fixture admitted sealed content")
        # This additional actor observes both actual 30-second release and
        # publisher retirement grace. Existing actors retain their 30s bound.
        result = actor("pin", "file-closure", timeout=120)
        require(result.returncode == 0 and result.stdout.splitlines() == [
            "PASS surface admission requires actual recovery and acknowledged Resume",
            "PASS active exposure blocks sealed body retirement after ordinary grace; draining retires the exact publisher inode while preserving exposure pins through final mapping and descriptor closure"],
            "actual sealed exposure retirement actor failed")
        result = actor("pin", "cold-closure")
        require(result.returncode == 0 and result.stdout.splitlines() == [
            "PASS surface admission requires actual recovery and acknowledged Resume",
            "PASS cold draining exposure preserves policy while the actual retired mapping survives; final unmap permits authenticated closure in funded recovery before Resume"],
            "actual cold exposure closure actor failed")
        objects = support.root("empty") / "objects"
        originals = list(objects.glob(".terrane-surface:2:*"))
        require(len(originals) == 1, "cold refusal has no unique real admitted index")
        original = originals[0]
        before = original.stat()
        original_bytes = original.read_bytes()
        malformed = objects / ".terrane-surface-tmp:bad"
        malformed.write_bytes(b"untrusted malformed cold index name")
        support.metadata(malformed, 840, 845, 0o600)
        result = actor("empty", "refuse-cold")
        require(result.returncode == 0 and result.stdout.splitlines() == [
            "PASS malformed cold surface namespace preserves original copy holds and refuses recovery"],
            "malformed cold surface namespace did not refuse recovery")
        after = original.stat()
        require((before.st_dev, before.st_ino, before.st_nlink) ==
                (after.st_dev, after.st_ino, after.st_nlink)
                and original.read_bytes() == original_bytes
                and malformed.read_bytes() == b"untrusted malformed cold index name",
                "cold refusal deleted or changed original candidate inodes")
        malformed.unlink()
        result = actor("empty", "exposure")
        require(result.returncode == 0 and result.stdout.splitlines() == [
            "PASS surface admission requires actual recovery and acknowledged Resume",
            "PASS scoped exposure root grants the original read-only index; changed policy and draining deny new grants while retained metadata remains readable",
            "PASS actual sealed exposure file is pinned before closing Read; ordinary release and draining preserve durable object protection",
            "PASS durable root exposure acknowledges original index context; cancellation retains obligations and renewal and expiry drain without releasing custody after receipt drop",
            "PASS durable exposure records match actual original index and file inodes and verity measurements; draining and receipt drop retain all bindings",
            "PASS authenticated census helper retains actual disclosed index custody and refuses an unconfigured owner and domain",
            "PASS draining index retirement closes owner descriptors; actual retained mapping prevents exposure release until final unmap and authenticated closure",
            "PASS cold exposure refuses recovery before mutation while kernel closure remains unreconciled"],
            "durable native root exposure actor failed")
        verify_surface(image, source)
        print("PASS actual native surface-index admission, cold retirement and separate cap; exposure pins and worker remain unqualified", flush=True)
    finally:
        for child in reversed(children):
            if child.poll() is None:
                child.send_signal(signal.SIGCONT)
                child.terminate()
                try:
                    child.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    child.kill()
                    child.wait(timeout=5)
        for log in logs:
            log.close()
        for name in ["helper", "publisher"]:
            path = support.RUNTIME / (name + ".log")
            if path.exists():
                print(name + " actual surface process log:\n" + path.read_text(errors="replace"), flush=True)


if __name__ == "__main__":
    main()
