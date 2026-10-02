"""Checks native stage bundles against real image archives and handoff units."""

import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import tempfile

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


def unit_values(contents, directive):
    """Read a resettable list directive from its Unit section."""
    section = None
    values = []
    for line in contents.splitlines():
        if line.startswith("["):
            section = line
        elif section == "[Unit]" and line.startswith(directive + "="):
            tokens = line.partition("=")[2].split()
            values = values + tokens if tokens else []
    return values


def check_units(tree, contract):
    completion = contract["handoff"]["completion_target"]
    switch_root = confined(
        tree,
        "etc/systemd/system/initrd-switch-root.target.d/50-aos-handoff.conf",
        "nix/store",
    ).read_text()
    require(completion in unit_values(switch_root, "Requires"), "switch-root does not require handoff completion")
    require(completion in unit_values(switch_root, "After"), "switch-root is not ordered after handoff completion")
    for name in contract["handoff"]["required_units"]:
        requirement = tree / "etc/systemd/system" / (completion + ".requires") / name
        require(requirement.is_symlink(), "missing handoff requirement")
        require(os.readlink(requirement) == "../" + name, "wrong handoff requirement")
        unit = confined(tree, "etc/systemd/system/" + name, "nix/store")
        require(completion in unit_values(unit.read_text(), "Before"), "handoff unit lacks exact Before ordering")


def check_rejected_unit_mutations(tree, contract):
    """Reject broken ordering using private copies of the archived unit bytes."""
    completion = contract["handoff"]["completion_target"]
    required_units = contract["handoff"]["required_units"]
    with tempfile.TemporaryDirectory(prefix="aos-handoff-units-") as directory:
        fixture = Path(directory)
        units = fixture / "etc/systemd/system"
        requirements = units / (completion + ".requires")
        requirements.mkdir(parents=True)
        switch_root = units / "initrd-switch-root.target.d/50-aos-handoff.conf"
        switch_root.parent.mkdir()
        archived_switch_root = confined(
            tree,
            "etc/systemd/system/initrd-switch-root.target.d/50-aos-handoff.conf",
            "nix/store",
        ).read_bytes()
        switch_root.write_bytes(archived_switch_root)
        for name in required_units:
            archived = confined(tree, "etc/systemd/system/" + name, "nix/store")
            (units / name).write_bytes(archived.read_bytes())
            (requirements / name).symlink_to("../" + name)
        check_units(fixture, contract)

        for contents in [
            "[Unit]\nAfter=" + completion + "\n",
            "[Unit]\nRequires=" + completion + "\n",
            "[Unit]\nRequires=" + completion + "\nRequires=\nAfter=" + completion + "\n",
            "[Unit]\nRequires=" + completion + "-unrelated\nAfter=" + completion + "\n",
        ]:
            switch_root.write_text(contents)
            try:
                check_units(fixture, contract)
            except ValueError:
                continue
            raise ValueError("handoff graph accepted incomplete switch-root prerequisites")
        switch_root.write_bytes(archived_switch_root)

        unit = units / required_units[0]
        mutations = [
            "[Service]\nBefore=" + completion + "\n",
            "[Unit]\nBefore=" + completion + "\nBefore=\n",
            "[Unit]\nBefore=" + completion + "-unrelated\n",
        ]
        for contents in mutations:
            unit.write_text(contents)
            try:
                check_units(fixture, contract)
            except ValueError:
                continue
            raise ValueError("handoff graph accepted invalid unit ordering")


def check_bundle(assembly, stage, tree, directory, store):
    names = ["transaction.json", "packages.json", "admission.json", "admission-sha256", "evaluation.json"]
    if stage == "host":
        names.append("installed.json")
    documents = {}
    if stage == "host":
        destination = tree / directory
        require(destination.is_dir() and not destination.is_symlink(), "host bundle is not a copied directory")
        require(
            not any(entry.name.endswith("-aos-profile-system-deployment") for entry in destination.iterdir()),
            "host bundle contains a nested bundle alias",
        )
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


def check_root_mountpoints(root):
    """Require the platform's baseline mountpoints in the actual immutable image."""
    for path, mode in (("srv", 0o755), ("root", 0o700), ("home", 0o755)):
        target = root / path
        require(target.is_dir() and not target.is_symlink(), "image lacks directory mountpoint /" + path)
        require(stat.S_IMODE(target.stat().st_mode) == mode, "image mountpoint mode differs: /" + path)


def check_minimal_base(root):
    """Reject workload payloads in the actual production root filesystem."""
    optional_payload = re.compile(
        r"^[0-9a-z]{32}-(?:tailscale|docker|docker-engine|docker-buildx|docker-compose|"
        r"containerd|qemu|qemu-img|libvirt|aos-hub|bind|dnsmasq)-[0-9]"
    )
    store = root / "usr/lib/aos/nix/store"
    unexpected = sorted(entry.name for entry in store.iterdir() if optional_payload.match(entry.name))
    require(not unexpected, "optional workload payloads retained in base: " + ", ".join(unexpected))

    installed = json.loads(confined(root, "usr/lib/aos/host/deployment/installed.json", "usr/lib/aos/nix/store").read_bytes())
    apm_roots = [record for record in installed if record["apm"]["name"] == "aos"]
    require(apm_roots, "base lacks the APM package")
    require(
        any((store / Path(record["store_path"]).name / "bin/apm").is_file() for record in apm_roots),
        "base lacks the installed APM executable",
    )


def main():
    assembly, contract_file, initrd, root = map(Path, sys.argv[1:5])
    contract = json.loads(contract_file.read_bytes())
    archive = assembly / "inputs/initrd.img"
    require(contract["artifact"]["size_bytes"] == archive.stat().st_size, "archive size differs")
    require(contract["artifact"]["sha256"] == "sha256:" + hashlib.sha256(archive.read_bytes()).hexdigest(), "archive digest differs")
    check_units(initrd, contract)
    check_rejected_unit_mutations(initrd, contract)
    check_bundle(assembly, "initrd", initrd, "lib/aos/initrd/deployment", "nix/store")
    check_bundle(assembly, "host", root, "usr/lib/aos/host/deployment", "usr/lib/aos/nix/store")
    check_root_mountpoints(root)
    check_minimal_base(root)
    # A runtime retained through a package dependency need not be a direct
    # closure root; verify the actual public executable in the archive.
    runtime = sys.argv[5]
    require(runtime.startswith("/nix/store/") and "/" not in runtime.removeprefix("/nix/store/"), "runtime is not a store root")
    runtime_executable = confined(initrd, runtime.removeprefix("/") + "/bin/aos-package-runtime", "nix/store")
    require(runtime_executable.is_file() and runtime_executable.stat().st_mode & 0o111, "public native runtime is not executable")
    require(not (root / "usr/lib/aos/boot-metadata-binding.json").is_symlink(), "image metadata binding is not a copied regular file")
    binding = confined(root, "usr/lib/aos/boot-metadata-binding.json", "usr/lib/aos/nix/store")
    require(binding.read_bytes() == Path(sys.argv[6]).read_bytes(), "image metadata binding differs from selected policy")
    for path in sys.argv[7:]:
        require(not (initrd / path.removeprefix("/")).exists(), "build-only output retained in initrd")
    require((initrd / "nix/var/nix/db").is_dir(), "initrd lacks writable native Nix state")
    require((initrd / "nix/var/nix/gcroots").is_dir(), "initrd lacks native retention directory")


if __name__ == "__main__":
    main()
