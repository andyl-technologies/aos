"""Checks native stage bundles against real image archives and handoff units."""

import hashlib
import json
import os
from pathlib import Path
import stat
import sys

LIMIT = 32 * 1024 * 1024


def require(condition, message):
    if not condition:
        raise ValueError(message)


def confined(root, relative, store, depth=0):
    """Resolve fixed bundle directories and bounded immutable member aliases."""
    require(depth < 8, "cyclic native archive alias")
    parts = Path(relative).parts
    require(parts and all(part not in (".", "..", "/") for part in parts), "unnormalized archive path")
    path = root
    for index, part in enumerate(parts):
        path = path / part
        if path.is_symlink():
            bundle = str(Path(*parts[:index + 1])) in {
                "lib/aos/initrd/deployment", "usr/lib/aos/initrd/deployment",
                "usr/lib/aos/host/deployment",
            }
            require(index == len(parts) - 1 or (depth == 0 and bundle), "linked archive parent")
            target = os.readlink(path)
            require(target.startswith("/nix/store/"), "document alias escapes store")
            suffix = target.removeprefix("/nix/store/")
            if index != len(parts) - 1:
                require("/" not in suffix and suffix not in ("", ".", ".."), "bundle alias is not a store root")
            relative_target = Path(store) / suffix
            return confined(root, str(relative_target.joinpath(*parts[index + 1:])), store, depth + 1)
    require(stat.S_ISREG(path.stat().st_mode), "document is not regular")
    require(path.stat().st_size <= LIMIT, "oversized native document")
    return path


def check_units(tree, contract):
    completion = contract["handoff"]["completion_target"]
    for name in contract["handoff"]["required_units"]:
        requirement = tree / "etc/systemd/system" / (completion + ".requires") / name
        require(requirement.is_symlink(), "missing handoff requirement")
        require(os.readlink(requirement) == "../" + name, "wrong handoff requirement")
        unit = confined(tree, "etc/systemd/system/" + name, "nix/store")
        section = None
        before = []
        for line in unit.read_text().splitlines():
            if line.startswith("["):
                section = line
            elif section == "[Unit]" and line.startswith("Before="):
                tokens = line.partition("=")[2].split()
                before = before + tokens if tokens else []
        require(completion in before, "handoff unit lacks exact Before ordering")


def check_rejected_unit_mutations(tree, contract):
    """Require the qualified graph check to reject broken handoff ordering."""
    name = contract["handoff"]["required_units"][0]
    unit = confined(tree, "etc/systemd/system/" + name, "nix/store")
    original = unit.read_bytes()
    completion = contract["handoff"]["completion_target"]
    mutations = [
        "[Service]\nBefore=" + completion + "\n",
        "[Unit]\nBefore=" + completion + "\nBefore=\n",
        "[Unit]\nBefore=" + completion + "-unrelated\n",
    ]
    try:
        for contents in mutations:
            unit.write_text(contents)
            try:
                check_units(tree, contract)
            except ValueError:
                continue
            raise ValueError("handoff graph accepted invalid unit ordering")
    finally:
        unit.write_bytes(original)
    check_units(tree, contract)


def check_bundle(assembly, stage, tree, directory, store):
    names = ["transaction.json", "packages.json", "admission.json", "admission-sha256", "evaluation.json"]
    if stage == "host":
        names.append("installed.json")
    documents = {}
    for name in names:
        captured = (assembly / "inputs" / (stage + "-deployment") / name).read_bytes()
        embedded = confined(tree, directory + "/" + name, store).read_bytes()
        require(captured == embedded, "native stage document differs from captured image input")
        documents[name] = captured
    transaction = json.loads(documents["transaction.json"])
    packages = json.loads(documents["packages.json"])
    evaluation = json.loads(documents["evaluation.json"])
    require(transaction["schema"] == "aos.package.transaction", "wrong native transaction")
    require(evaluation["schema"] == "aos.package.evaluation-input", "wrong native descriptor")
    require(evaluation["packages"] == packages, "descriptor package context differs")
    require(transaction["artifacts"] == packages["artifacts"], "transaction payloads differ")
    require(transaction["packages"] == packages["modules"], "transaction modules differ")
    require(transaction["scope"] == evaluation["scope"], "descriptor scope differs")
    require(transaction["scope"] == ["profile", "system"] if stage == "host" else transaction["scope"][-1] == "initrd", "wrong stage scope")
    digest = "sha256:" + hashlib.sha256(documents["admission.json"]).hexdigest()
    require(documents["admission-sha256"].decode().strip() == digest, "admission bytes changed")


def main():
    assembly, contract_file, initrd, root = map(Path, sys.argv[1:5])
    contract = json.loads(contract_file.read_bytes())
    archive = assembly / "inputs/initrd.img"
    require(contract["artifact"]["size_bytes"] == archive.stat().st_size, "archive size differs")
    require(contract["artifact"]["sha256"] == "sha256:" + hashlib.sha256(archive.read_bytes()).hexdigest(), "archive digest differs")
    check_units(initrd, contract)
    check_rejected_unit_mutations(initrd, contract)
    check_bundle(assembly, "initrd", initrd, "lib/aos/initrd/deployment", "nix/store")
    check_bundle(assembly, "host", root, "usr/lib/aos/host/deployment", "nix.lower/store")
    for path in sys.argv[5:]:
        require(not (initrd / path.removeprefix("/")).exists(), "build-only output retained in initrd")
    require((initrd / "nix/var/nix/db").is_dir(), "initrd lacks writable native Nix state")
    require((initrd / "nix/var/nix/gcroots").is_dir(), "initrd lacks native retention directory")


if __name__ == "__main__":
    main()
