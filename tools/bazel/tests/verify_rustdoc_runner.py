"""Executes the pinned doctest writer and verifies literal Unix shell inputs."""

import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile


def verify(writer, bash):
    with tempfile.TemporaryDirectory(prefix="aos-rustdoc-quoting-") as directory:
        root = Path(directory)
        probe = root / "probe.py"
        probe.write_text(
            "import json, os, sys\n"
            "print(json.dumps({'value': os.environ['AOS_QUOTED_METADATA'], 'args': sys.argv[1:]}))\n"
        )
        runner = root / "runner"
        value = "the registry's static pages; $(touch metadata-expanded); `touch backtick-expanded`\nsecond line"
        arguments = ["a quoted ' argument", 'double " quotes', "$(touch argument-expanded)", "line\nbreak", ""]
        environment = dict(os.environ, AOS_QUOTED_METADATA=value)
        subprocess.run(
            [str(writer), "--output=" + str(runner),
             "--optional_test_params=" + str(root / "parameters"),
             "--action_env=AOS_QUOTED_METADATA", "--",
             sys.executable, str(probe), *arguments],
            env=environment, cwd=root, check=True,
        )
        result = subprocess.run([str(bash), str(runner)], cwd=root, check=True, capture_output=True, text=True)
        observed = json.loads(result.stdout)
        if observed != {"value": value, "args": arguments}:
            raise ValueError("doctest runner changed metadata or command arguments")
        for name in ["metadata-expanded", "backtick-expanded", "argument-expanded"]:
            if (root / name).exists():
                raise ValueError("doctest runner interpreted a literal shell expression")
        return {"status": "PASS", "metadata_preserved": True, "arguments_preserved": len(arguments),
                "shell_expressions_executed": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--writer", type=Path, required=True)
    parser.add_argument("--bash", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    options = parser.parse_args()
    options.output.write_text(json.dumps(verify(options.writer, options.bash), indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    main()
