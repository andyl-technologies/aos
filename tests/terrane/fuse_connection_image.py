"""Installs the actual FUSE connection fixture and binds its native driver."""

import hashlib
import json
import os
from pathlib import Path

from structural_mapping_image import main


if __name__ == "__main__":
    main(example="fuse_connection_fixture", executable_name="fuse-connection-fixture",
         scope="Original FUSE transport component; no repository or production worker acceptance",
         features=("native-test-fixtures", "surface-fuse", "tokio"))
    output = Path(os.environ["out"])
    source = Path(os.environ["src"])
    identity = json.loads((output / "identity.json").read_text())
    identity["fixture_inputs_sha256"] = {
        relative: hashlib.sha256((source / relative).read_bytes()).hexdigest()
        for relative in ["tests/terrane/fuse_connection_image.py",
                         "tests/terrane/fuse_connection_vm.py",
                         "tests/terrane/fuse-connection.nix",
                         "tests/terrane/structural_mapping_image.py"]
    }
    (output / "identity.json").write_text(json.dumps(identity, indent=2) + "\n")
