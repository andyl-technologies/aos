"""Prepares canonical immutable bootstrap aliases with explicit native custody.

Rendering reuses the normal service and resource-group implementations. The
installation operation never contacts a running manager. Its roots retain every
immutable seed until no pending native recipient depends on that seed.
"""

import argparse
import hashlib
import importlib.util
import json
import os
import re
from pathlib import Path
import stat
import subprocess
import sys
import tempfile

from aos_service_resources import durable_unlink, durable_write, locked_dispatch, read_invocation


def digest(value):
    return hashlib.sha256(value).hexdigest()


def regular_json(path):
    real_parents(Path(path))
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except FileNotFoundError:
        return None
    with os.fdopen(descriptor, "rb") as source:
        metadata = os.fstat(source.fileno())
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > 4 * 1024 * 1024:
            raise ValueError("bootstrap receipt is not a bounded regular file")
        return json.load(source)


def real_parents(path):
    for parent in reversed(path.parents):
        try:
            metadata = parent.lstat()
        except FileNotFoundError:
            continue
        if not stat.S_ISDIR(metadata.st_mode):
            raise ValueError("bootstrap resource ancestor is not a real directory")


def checked_name(name):
    path = Path(name)
    if path.is_absolute() or not path.parts or any(part in {"", ".", ".."} for part in name.split("/")):
        raise ValueError("bootstrap unit name contains traversal")
    return name


class Bootstrap:
    def __init__(self, invocation, renderer, args):
        self.invocation = invocation
        self.value = invocation["input"]
        self.renderer = renderer
        self.args = args
        self.key = digest(invocation["id"].encode())
        self.state = Path(args.state_directory)
        self.path = self.state / (self.key + ".json")
        self.receipt = regular_json(self.path)
        if self.receipt is not None and self.receipt.get("owner") != invocation["id"]:
            raise ValueError("bootstrap receipt owner differs")
        self.units = Path(args.unit_directory)
        self.roots = Path(args.root_directory)

    def save(self, receipt):
        real_parents(self.path)
        self.state.mkdir(parents=True, exist_ok=True, mode=0o700)
        encoded = json.dumps(receipt, sort_keys=True).encode()
        if len(encoded) > 4 * 1024 * 1024:
            raise ValueError("bootstrap receipt exceeds its durable byte bound")
        durable_write(self.path, encoded, 0o600)
        self.receipt = receipt

    def command(self, *arguments, input=None):
        result = subprocess.run(arguments, input=input, capture_output=True, check=False)
        if result.returncode:
            raise RuntimeError("bootstrap command failed: " + result.stderr.decode(errors="replace")[:4096])
        return result.stdout.decode().strip()

    def render(self):
        with tempfile.TemporaryDirectory(prefix="aos-systemd-bootstrap-") as directory:
            tree = Path(directory) / "systemd-bootstrap"
            self.renderer.render_services(self.value["services"], tree)
            self.command(self.args.group_renderer, "render-resource-groups", "--output-dir", str(tree),
                         input=json.dumps(self.value["groups"]).encode())
            entries = {}
            for name, service in self.value["services"].items():
                realization = self.renderer.realize_service(service)
                recipient = self.value["serviceRecipients"][name]
                for unit, text in realization["units"].items():
                    entries[checked_name(unit)] = {"kind": "service", "recipient": recipient,
                                                  "digest": digest(text.encode()), "link": None}
                for link, target in realization["links"].items():
                    entries[checked_name(link)] = {"kind": "service", "recipient": recipient,
                                                  "digest": None, "link": target}
            for group in self.value["groups"]:
                if group["bootstrap"]:
                    name = group["name"] + ".slice"
                    entries[checked_name(name)] = {"kind": "group", "recipient": self.value["groupRecipients"][group["name"]],
                                                  "digest": digest((tree / name).read_bytes()), "link": None}
            content_hash = self.command(self.args.nix_hash, "--type", "sha256", "--base32", str(tree))
            predicted = self.command(self.args.nix_store, "--print-fixed-path", "--recursive", "sha256", content_hash, tree.name)
            if not re.fullmatch(r"/nix/store/[0-9abcdfghijklmnpqrsvwxyz]{32}-[^/]+", predicted):
                raise ValueError("bootstrap prediction is not one canonical store root")
            self.retain_root_intent(predicted)
            # The persistent root exists before import's temporary root expires.
            self.pin(predicted)
            root = self.command(self.args.nix_store, "--add-fixed", "--recursive", "sha256", str(tree))
            if root != predicted:
                raise ValueError("bootstrap import differs from its pinned content identity")
        if not re.fullmatch(r"/nix/store/[0-9abcdfghijklmnpqrsvwxyz]{32}-[^/]+", root):
            raise ValueError("bootstrap import did not produce one canonical store root")
        nar_hash = self.command(self.args.nix_store, "--query", "--hash", root)
        for name, entry in entries.items():
            entry["target"] = entry["link"] if entry["link"] is not None else root + "/" + name
        return root, nar_hash, entries

    def retain_root_intent(self, root):
        # Import and destination validation may fail before alias publication.
        # Record the root first so recovery or removal can reclaim its exact pin.
        receipt = dict(self.receipt or {
            "owner": self.invocation["id"], "revision": self.invocation["revision"],
            "root": root, "digest": None, "entries": {}, "previous": {}, "history": [],
        })
        receipt["roots"] = list(dict.fromkeys([*receipt.get("roots", []), root]))
        receipt["pending"] = True
        self.save(receipt)

    def recipient(self, entry):
        key = digest(entry["recipient"].encode())
        if entry["kind"] == "service":
            path = Path(self.args.service_state_directory) / (key + ".json")
            receipt = regular_json(path)
            if receipt is not None and receipt.get("id") != entry["recipient"]:
                raise ValueError("bootstrap service recipient identity differs")
        else:
            path = Path(self.args.group_state_directory) / (key + "-unit.json")
            receipt = regular_json(path)
            if receipt is not None and receipt.get("owner") != entry["recipient"]:
                raise ValueError("bootstrap group recipient identity differs")
        return receipt

    def adopted(self, name, entry):
        receipt = self.recipient(entry)
        if receipt is None:
            return False
        path = self.units / name
        if entry["kind"] == "service":
            if entry["link"] is not None:
                return receipt.get("links", {}).get(name) == entry["target"] and path.is_symlink() and os.readlink(path) == entry["target"]
            expected = receipt.get("units", {}).get(name)
            custody = receipt.get("image_units", {}).get(name)
            if custody is not None and custody != {"target": entry["target"], "digest": entry["digest"]}:
                return False
        else:
            desired = receipt.get("desired", {})
            if desired.get("unit") != name:
                return False
            expected = digest(desired.get("text", "").encode())
            custody = receipt.get("image")
            if custody is not None and custody != {"target": entry["target"], "seed_digest": entry["digest"]}:
                return False
        if path.is_symlink():
            return False
        return expected is not None and self.renderer.read_digest(path) == expected

    def exact_alias(self, name, entry):
        path = self.units / name
        real_parents(path)
        if not path.is_symlink() or os.readlink(path) != entry["target"]:
            return False
        if entry["link"] is None and self.renderer.image_unit_digest(entry["target"]) != entry["digest"]:
            raise ValueError("bootstrap immutable seed content changed")
        return True

    def check(self, name, entry):
        path = self.units / name
        if self.exact_alias(name, entry):
            return "prepared"
        if self.adopted(name, entry):
            return "adopted"
        if path.exists() or path.is_symlink():
            raise ValueError("bootstrap definition was replaced outside its native recipient")
        return "absent"

    def pin(self, root):
        real_parents(self.roots / "entry")
        self.roots.mkdir(parents=True, exist_ok=True, mode=0o700)
        path = self.roots / (self.key + "-" + digest(root.encode()))
        if path.is_symlink():
            if os.readlink(path) != root:
                raise ValueError("bootstrap GC root was replaced")
        elif path.exists():
            raise ValueError("bootstrap GC root is not an owned alias")
        else:
            path.symlink_to(root)
        descriptor = os.open(self.roots, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    def outputs(self):
        return {"resource": "systemd-bootstrap:" + self.invocation["id"],
                "storePath": self.receipt["root"], "digest": self.receipt["digest"]}

    def apply(self):
        root, nar_hash, entries = self.render()
        previous = dict((self.receipt or {}).get("entries", {}))
        # A crash can leave predecessor aliases after the new intent is durable.
        # Select their exact retained entry rather than treating them as foreign.
        predecessors = (self.receipt or {}).get("previous", {})
        for name, old in predecessors.items():
            if self.exact_alias(name, old):
                previous[name] = old
        adopted = set()
        for name in entries.keys() | previous.keys():
            old = previous.get(name)
            new = entries.get(name)
            if old is not None:
                status = self.check(name, old)
                if status == "adopted":
                    adopted.add(name)
            elif new is not None and self.check(name, new) != "absent":
                raise ValueError("bootstrap destination exists without preparation custody")
        roots = list(dict.fromkeys([*(self.receipt or {}).get("roots", []), root]))
        self.pin(root)
        receipt = {"owner": self.invocation["id"], "revision": self.invocation["revision"],
                   "root": root, "digest": nar_hash, "roots": roots, "entries": entries,
                   "previous": previous, "pending": True,
                   "history": (self.receipt or {}).get("history", []) + [
                       {"name": name, "entry": entry} for name, entry in previous.items()
                       if {"name": name, "entry": entry} not in (self.receipt or {}).get("history", [])
                   ]}
        self.save(receipt)
        for name, old in previous.items():
            if name not in entries and name not in adopted and self.exact_alias(name, old):
                durable_unlink(self.units / name)
        for name, entry in entries.items():
            if name in adopted:
                continue
            path = self.units / name
            path.parent.mkdir(parents=True, exist_ok=True)
            if self.exact_alias(name, entry):
                continue
            old = previous.get(name)
            if old is not None and self.exact_alias(name, old):
                durable_unlink(path)
            path.symlink_to(entry["target"])
            descriptor = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        self.save(dict(receipt, pending=False, previous={}))
        return self.outputs()

    def observe(self):
        if self.receipt is None:
            return {"status": "absent"}
        if self.invocation.get("action") == "remove":
            return {"status": "retry-safe"}
        if self.receipt.get("pending") or self.receipt.get("revision") != self.invocation["revision"]:
            return {"status": "retry-safe"}
        for name, entry in self.receipt["entries"].items():
            if self.check(name, entry) == "absent":
                return {"status": "retry-safe"}
        self.command(self.args.nix_store, "--check-validity", self.receipt["root"])
        if self.command(self.args.nix_store, "--query", "--hash", self.receipt["root"]) != self.receipt["digest"]:
            raise ValueError("bootstrap immutable tree identity changed")
        return {"status": "current", "outputs": self.outputs()}

    def remove(self):
        if self.receipt is None:
            return {}
        entries = dict(self.receipt.get("previous", {}), **self.receipt["entries"])
        for name, predecessor in self.receipt.get("previous", {}).items():
            if self.exact_alias(name, predecessor):
                entries[name] = predecessor
        statuses = {name: self.check(name, entry) for name, entry in entries.items()}
        history = self.receipt.get("history", []) + [
            {"name": name, "entry": entry} for name, entry in entries.items()
        ]
        for item in history:
            entry = item["entry"]
            recipient = self.recipient(entry)
            if entry["kind"] == "service":
                custody = (recipient or {}).get("image_units", {}).get(item["name"])
                retained = custody == {"target": entry["target"], "digest": entry["digest"]}
            else:
                custody = (recipient or {}).get("image")
                retained = custody == {"target": entry["target"], "seed_digest": entry["digest"]}
            if retained:
                # Consumers retire first through their typed graph dependency.
                # A pending handoff cannot become an apparently finished removal.
                raise ValueError("bootstrap seed remains in native recipient custody")
        for name, status in statuses.items():
            if status == "prepared":
                durable_unlink(self.units / name)
        for root in self.receipt["roots"]:
            path = self.roots / (self.key + "-" + digest(root.encode()))
            real_parents(path)
            if path.is_symlink() and os.readlink(path) == root:
                durable_unlink(path)
            elif path.exists() or path.is_symlink():
                raise ValueError("bootstrap GC root was replaced")
        durable_unlink(self.path)
        return {}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--nix-store", required=True)
    parser.add_argument("--nix-hash", required=True)
    parser.add_argument("--group-renderer", required=True)
    parser.add_argument("--true-executable", required=True)
    parser.add_argument("--flock-executable", required=True)
    parser.add_argument("--mac-condition-executable", required=True)
    parser.add_argument("--state-directory", default="/var/lib/aos/systemd-bootstrap")
    parser.add_argument("--unit-directory", default="/etc/systemd/system")
    parser.add_argument("--root-directory", default="/nix/var/nix/gcroots/aos/systemd-bootstrap")
    parser.add_argument("--service-state-directory", default="/var/lib/aos/native-service-effects")
    parser.add_argument("--group-state-directory", default="/var/lib/aos/systemd-resources")
    parser.add_argument("action", choices=["apply", "observe", "remove"])
    args = parser.parse_args()
    spec = importlib.util.spec_from_file_location("aos_service_renderer", Path(__file__).with_name("aos-service-handler.py"))
    renderer = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(renderer)
    renderer.TRUE_EXECUTABLE = args.true_executable
    renderer.FLOCK_EXECUTABLE = args.flock_executable
    renderer.MAC_CONDITION_EXECUTABLE = args.mac_condition_executable
    invocation = read_invocation()
    if invocation["effect"]["identity"][-3:-1] != ["systemdBootstrap", "prepare"]:
        raise ValueError("unsupported systemd bootstrap operation")
    result = locked_dispatch(args.state_directory, lambda _: getattr(Bootstrap(invocation, renderer, args), args.action)())
    print(json.dumps(result, separators=(",", ":")))


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print("systemd bootstrap: " + str(error), file=sys.stderr)
        sys.exit(1)
