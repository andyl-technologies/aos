"""Checks native preparation under real private allocation mount views.

Only the guest supervisor creates mount namespaces. Each native factory runs
under the original capability-free cache identity and authenticated endpoints.
No mutable owner starts, and the original cache-state bytes must survive.
"""

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys


ALLOCATIONS = ["chunks", "objects", "quarantine", "state/cache"]


def require(condition, message):
    """Refuses an incomplete native mount-policy witness."""
    if not condition:
        raise RuntimeError(message)


def snapshot(root):
    """Records actual cache-state names, custody and file bytes."""
    result = {}
    state = root / "state/cache"
    for path in [state, *sorted(state.rglob("*"))]:
        value = path.lstat()
        require(not path.is_symlink(), "unexpected cache-state symlink")
        result[str(path.relative_to(root))] = {
            "device": value.st_dev, "inode": value.st_ino,
            "mode": value.st_mode, "uid": value.st_uid, "gid": value.st_gid,
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else None,
        }
    return result


def namespace(root, readonly, command):
    """Creates guest-only binds before dropping to the original cache identity."""
    require(os.geteuid() == 0 and readonly in ["writable", *ALLOCATIONS[:3]],
            "invalid explicit mount-policy setup")
    subprocess.run(["mount", "--make-rprivate", "/"], check=True, timeout=5)
    for label in [".", *ALLOCATIONS]:
        path = str(root / label)
        subprocess.run(["mount", "--bind", path, path], check=True, timeout=5)
    subprocess.run(["mount", "-o", "remount,bind,ro", str(root)], check=True, timeout=5)
    if readonly != "writable":
        subprocess.run(["mount", "-o", "remount,bind,ro", str(root / readonly)],
                       check=True, timeout=5)
    os.execvpe(command[0], command, dict(os.environ))


def verify(root, readonly, command):
    """Observes actual unprivileged mount flags before exec of the native factory."""
    require(os.getuid() == os.geteuid() == os.getgid() == os.getegid() == 840,
            "allocation witness has another identity")
    require(set(os.getgroups()) == {844, 845}, "allocation witness has other groups")
    status = dict(line.split(":", 1) for line in Path("/proc/self/status").read_text().splitlines()
                  if ":" in line)
    require(status["NoNewPrivs"].strip() == "1" and all(int(status[name], 16) == 0
            for name in ["CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"]),
            "allocation witness lacks original confinement")
    observations = {}
    for label in [".", *ALLOCATIONS]:
        path = root / label
        value = path.stat()
        actual = bool(os.statvfs(path).f_flag & os.ST_RDONLY)
        require(actual == (label == "." or label == readonly), "allocation mount flags differ")
        observations[label] = {"readonly": actual, "device": value.st_dev, "inode": value.st_ino}

    print("NATIVE_ALLOCATION_MOUNT_POLICY " + json.dumps({
        "case": readonly, "uid": os.getuid(), "gid": os.getgid(),
        "groups": os.getgroups(), "capabilities": 0, "nnp": 1, "roots": observations,
    }, sort_keys=True), flush=True)
    os.execvpe(command[0], command, dict(os.environ))


def run(driver, uuid):
    """Requires successful preparation and refusal of each read-only allocation."""
    root = driver.root("empty")
    original = snapshot(root)
    bindings = {label: (root / label).stat() for label in [".", *ALLOCATIONS]}
    for readonly in ["writable", *ALLOCATIONS[:3], "writable"]:
        mode = "prepare" if readonly == "writable" else "prepare-readonly-refuse"
        native = [str(driver.IMAGE / "bin/host_cache_fixture"), mode]
        verify_command = [sys.executable, str(Path(__file__)), "verify", str(root), readonly,
                          json.dumps(native)]
        role = driver.role_command(840, verify_command)
        role.insert(1, "--no-new-privs")
        command = ["unshare", "--mount", "--fork", sys.executable, str(Path(__file__)),
                   "namespace", str(root), readonly, json.dumps(role)]
        result = subprocess.run(command, env=driver.actor_environment("empty", uuid),
                                capture_output=True, text=True, timeout=30)
        print(result.stdout, end="", flush=True)
        if result.stderr:
            print(result.stderr, end="", flush=True)
        require(result.returncode == 0, "actual allocation mount factory case failed")
        rows = [json.loads(line.removeprefix("NATIVE_ALLOCATION_MOUNT_POLICY "))
                for line in result.stdout.splitlines() if line.startswith("NATIVE_ALLOCATION_MOUNT_POLICY ")]
        require(len(rows) == 1 and rows[0]["case"] == readonly, "missing exact mount-policy witness")
        for label, expected in bindings.items():
            actual = rows[0]["roots"][label]
            require((actual["device"], actual["inode"]) == (expected.st_dev, expected.st_ino),
                    "allocation bind replaced its original inode")
        expected = ("PASS actual native preparation; no recovery or Resume" if readonly == "writable"
                    else "PASS actual read-only allocation mount refused before mutable owner startup")
        require(result.stdout.splitlines().count(expected) == 1 and snapshot(root) == original,
                "native mount-policy case lacks its result or changed cache state")
        require(not os.statvfs(root).f_flag & os.ST_RDONLY,
                "private mount-policy case changed the supervisor namespace")

    print("PASS native allocation mount views: writable preparation, three read-only refusals, "
          "fresh writable preparation and unchanged original state", flush=True)


if __name__ == "__main__":
    action, root, readonly, encoded = sys.argv[1:]
    {"namespace": namespace, "verify": verify}[action](Path(root), readonly, json.loads(encoded))
