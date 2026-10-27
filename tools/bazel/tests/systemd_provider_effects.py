"""Exercises installed seed rendering and retained-store admission without PID 1."""

import hashlib
import json
from pathlib import Path
import subprocess
import tempfile


def invoke(program, arguments, data=b""):
    """Captures an installed command with bounded execution time."""
    result = subprocess.run([str(program), *map(str, arguments)], input=data,
                            capture_output=True, timeout=30)
    return result.returncode, result.stdout, result.stderr


def exercise(package, nix_store):
    """Checks real filesystem effects and rejects substituted retained inputs."""
    renderer = Path(package) / "bin/aos-systemd-native-resource-provider"
    restore = Path(package) / "bin/aos-systemd-initrd-store"
    records = {}
    with tempfile.TemporaryDirectory(prefix="systemd-provider-effects-") as temporary:
        root = Path(temporary)
        output = root / "units"
        seeds = json.dumps([
            {"name": "aos-pkg-nginx", "description": "Package workers at 50%", "bootstrap": True},
            {"name": "aos-pkg-envoy", "bootstrap": False},
        ]).encode()
        result = invoke(renderer, ["render-resource-groups", "--output-dir", output], seeds)
        expected = b"[Unit]\nDescription=Package workers at 50%%\n\n[Slice]\n"
        if (result != (0, b"", b"") or sorted(path.name for path in output.iterdir()) != ["aos-pkg-nginx.slice"]
                or (output / "aos-pkg-nginx.slice").read_bytes() != expected):
            raise ValueError("installed renderer changed bootstrap selection or slice contents")
        records["bootstrap_seed"] = {"sha256": hashlib.sha256(expected).hexdigest(), "entries": 1}

        result = invoke(renderer, ["render-resource-groups", "--output-dir", output], seeds)
        if result[0] != 1 or b"resource group seed already exists" not in result[2]:
            raise ValueError("installed renderer overwrote an existing seed")
        if (output / "aos-pkg-nginx.slice").read_bytes() != expected:
            raise ValueError("rejected seed replacement changed the existing file")
        records["existing_seed_preserved"] = True

        invalid = root / "invalid"
        data = b'[{"name":"aos-pkg-nginx","bootstrap":true,"untrusted":true}]'
        result = invoke(renderer, ["render-resource-groups", "--output-dir", invalid], data)
        if result[0] != 1 or invalid.exists():
            raise ValueError("invalid seed fields produced filesystem effects")
        records["unknown_seed_field_rejected_before_effects"] = True

        alias = root / "alias"
        alias.symlink_to(output, target_is_directory=True)
        result = invoke(renderer, ["render-resource-groups", "--output-dir", alias], seeds)
        if result[0] != 1 or sorted(path.name for path in output.iterdir()) != ["aos-pkg-nginx.slice"]:
            raise ValueError("seed renderer followed a mutable output alias")
        records["output_alias_rejected"] = True

        journal = root / "journal"
        journal.mkdir()
        arguments = ["--nix-store", nix_store, "--state-directory", journal]
        if invoke(restore, arguments) != (0, b"", b"") or list(journal.iterdir()):
            raise ValueError("absent retained snapshot did not restore without mutation")
        records["absent_snapshot"] = True

        directory = journal / "retained-store"
        directory.mkdir()
        manifest = directory / "manifest.json"
        empty = {"schema": "aos.initrd-retained-store", "roots": [], "payload": None}
        manifest.write_text(json.dumps(empty))
        original = manifest.read_bytes()
        if invoke(restore, arguments) != (0, b"", b"") or manifest.read_bytes() != original:
            raise ValueError("empty retained snapshot did not preserve its manifest")
        records["empty_snapshot"] = True

        manifest.write_text(json.dumps({**empty, "schema": "untrusted"}))
        result = invoke(restore, arguments)
        if result[0] != 1 or b"unknown retained store manifest" not in result[2]:
            raise ValueError("retained snapshot accepted an unknown schema")
        records["unknown_snapshot_schema_rejected"] = True

        manifest.unlink()
        target = root / "external-manifest.json"
        target.write_text(json.dumps(empty))
        manifest.symlink_to(target)
        result = invoke(restore, arguments)
        if result[0] != 1 or b"manifest is not a regular file" not in result[2]:
            raise ValueError("retained snapshot accepted an aliased manifest")
        records["manifest_alias_rejected"] = True

    return records


def compare(packages, nix_store):
    """Requires the same successful effects and admission checks from both drivers."""
    records = {driver: exercise(outputs["out"], nix_store) for driver, outputs in packages.items()}
    if set(records) != {"ordinary", "bazel"} or records["ordinary"] != records["bazel"]:
        raise ValueError("installed systemd provider filesystem effects differ")
    return {"schema_version": 1, "drivers": records,
            "limits": ["No live DBus manager, encrypted credentials, image staging or nonempty store import is exercised here."]}
