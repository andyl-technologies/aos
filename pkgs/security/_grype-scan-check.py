"""Qualifies offline cataloging and scanning with real upstream advisory data."""

import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile


def write_json(path, value):
    path.write_text(json.dumps(value, sort_keys=True), encoding="utf-8")


def blob(layout, payload):
    digest = hashlib.sha256(payload).hexdigest()
    (layout / "blobs" / "sha256" / digest).write_bytes(payload)
    return {"digest": f"sha256:{digest}", "size": len(payload)}


def fixture_image(layout):
    """Builds an OCI fixture whose package metadata names vulnerable Lodash."""
    (layout / "blobs" / "sha256").mkdir(parents=True)
    archive = io.BytesIO()
    metadata = json.dumps({"name": "lodash", "version": "4.17.20"}).encode()
    with tarfile.open(fileobj=archive, mode="w") as layer:
        entry = tarfile.TarInfo("app/node_modules/lodash/package.json")
        entry.size = len(metadata)
        entry.mode = 0o644
        layer.addfile(entry, io.BytesIO(metadata))

    layer = blob(layout, archive.getvalue())
    layer["mediaType"] = "application/vnd.oci.image.layer.v1.tar"
    config = blob(
        layout,
        json.dumps(
            {
                "architecture": "amd64",
                "os": "linux",
                "config": {},
                "rootfs": {"type": "layers", "diff_ids": [layer["digest"]]},
            },
            sort_keys=True,
        ).encode(),
    )
    config["mediaType"] = "application/vnd.oci.image.config.v1+json"
    manifest = blob(
        layout,
        json.dumps(
            {"schemaVersion": 2, "config": config, "layers": [layer]},
            sort_keys=True,
        ).encode(),
    )
    manifest["mediaType"] = "application/vnd.oci.image.manifest.v1+json"
    write_json(layout / "index.json", {"schemaVersion": 2, "manifests": [manifest]})
    write_json(layout / "oci-layout", {"imageLayoutVersion": "1.0.0"})


def run(command, environment, cwd, expected_success=True):
    result = subprocess.run(
        command, env=environment, cwd=cwd, capture_output=True, text=True, check=False
    )
    if (result.returncode == 0) != expected_success:
        raise RuntimeError(
            f"command returned {result.returncode}: {command!r}\n"
            f"{result.stdout}\n{result.stderr}"
        )
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--grype", required=True)
    parser.add_argument("--syft", required=True)
    parser.add_argument("--database", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory(prefix="grype-qualification-") as temporary:
        work = Path(temporary)
        layout = work / "image"
        fixture_image(layout)
        environment = {
            key: value
            for key, value in os.environ.items()
            if not key.startswith(("GRYPE_", "SYFT_"))
        }
        environment.update(
            {
                "GRYPE_CHECK_FOR_APP_UPDATE": "false",
                "GRYPE_DB_AUTO_UPDATE": "false",
                "GRYPE_DB_CACHE_DIR": str(work / "database"),
                "GRYPE_DB_VALIDATE_BY_HASH_ON_START": "true",
                # Immutable historical qualification data is deliberately not
                # a delivery database; production CI keeps age checks enabled.
                "GRYPE_DB_VALIDATE_AGE": "false",
                "SYFT_CHECK_FOR_APP_UPDATE": "false",
            }
        )
        config = work / "empty-config.yaml"
        config.write_text("{}\n", encoding="utf-8")
        catalog = args.output / "catalog.syft.json"
        run(
            [
                args.syft,
                "-c",
                str(config),
                f"oci-dir:{layout}",
                "-o",
                f"syft-json={catalog}",
            ],
            environment,
            work,
        )
        inventory = json.loads(catalog.read_text(encoding="utf-8"))
        if not any(
            package.get("name") == "lodash"
            and package.get("version") == "4.17.20"
            and package.get("type") == "npm"
            for package in inventory.get("artifacts", [])
        ):
            raise RuntimeError("OCI fixture was not cataloged as the expected npm package")

        run(
            [args.grype, "-c", str(config), "db", "import", args.database],
            environment,
            work,
        )
        status = run(
            [args.grype, "-c", str(config), "db", "status", "-o", "json"], environment, work
        )
        database_status = json.loads(status.stdout)
        if (
            not database_status.get("valid")
            or database_status.get("schemaVersion") != "v6.1.9"
        ):
            raise RuntimeError(f"unexpected real database status: {database_status!r}")
        write_json(args.output / "database-status.json", database_status)

        report = args.output / "vulnerabilities.json"
        run(
            [
                args.grype,
                "-c",
                str(config),
                f"sbom:{catalog}",
                "-o",
                f"json={report}",
                "--fail-on",
                "high",
            ],
            environment,
            work,
            expected_success=False,
        )
        findings = json.loads(report.read_text(encoding="utf-8"))
        if not any(
            match.get("artifact", {}).get("name") == "lodash"
            and match.get("vulnerability", {}).get("id")
            in {"CVE-2021-23337", "GHSA-35jh-r3h4-6jhm"}
            for match in findings.get("matches", [])
        ):
            raise RuntimeError(
                "scanner failed to detect the real Lodash command injection advisory"
            )

        environment["GRYPE_DB_CACHE_DIR"] = str(work / "absent-database")
        missing = run(
            [args.grype, "-c", str(config), f"sbom:{catalog}", "-o", "json"],
            environment,
            work,
            expected_success=False,
        )
        if len(missing.stderr) > 16 << 10 or "database does not exist" not in missing.stderr:
            raise RuntimeError("missing database scan failed for an unrelated reason")
        (args.output / "missing-database.log").write_text(missing.stderr, encoding="utf-8")


if __name__ == "__main__":
    main()
