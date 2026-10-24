"""Checks each compiled native feature profile before its VM execution credit."""

import json
import os
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).parent))
from native_sdk_test_image import source_hashes


def main():
    """Requires the actual native libtest artifact and unchanged source inputs."""
    workspace = Path.cwd()
    source = Path(os.environ["src"])
    source_hashes(workspace, source)
    rows = [json.loads(line) for line in Path(sys.argv[1]).read_text().splitlines()]
    artifacts = [row for row in rows if row.get("reason") == "compiler-artifact"
                 and row.get("target", {}).get("name") == "terrane_linux"
                 and row.get("profile", {}).get("test") is True
                 and row.get("executable")]
    if len(artifacts) != 1:
        raise SystemExit("missing or ambiguous native feature libtest artifact")
    artifact = artifacts[0]
    profiles = {
        "base": ["native-test-fixtures", "tokio"],
        "all": ["native-test-fixtures", "surface-fuse", "tokio"],
    }
    if len(sys.argv) != 3 or sys.argv[2] not in profiles:
        raise SystemExit("missing explicit native feature profile")
    package = workspace / "terrane/linux/terrane-linux"
    profile = artifact["profile"]
    executable = Path(artifact["executable"])
    if (artifact["features"] != profiles[sys.argv[2]]
            or not artifact["package_id"].startswith("path+file://" + str(package))
            or artifact["target"]["kind"] != ["lib"]
            or artifact["target"]["crate_types"] != ["lib"]
            or Path(artifact["target"]["src_path"]) != package / "src/lib.rs"
            or profile["opt_level"] != "s" or profile["debuginfo"] != 0
            or profile["debug_assertions"] is not True
            or not executable.resolve().is_relative_to(Path(os.environ["CARGO_TARGET_DIR"]).resolve())
            or not executable.read_bytes().startswith(b"\x7fELF")):
        raise SystemExit("native feature source, profile, features or executable mismatch")
    print("PASS actual native feature profile compiled; full execution requires the native VM proof")


if __name__ == "__main__":
    main()
