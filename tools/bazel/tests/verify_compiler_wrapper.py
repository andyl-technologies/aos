"""Compares reconstructed inputs with a source-built pinned process wrapper."""

import argparse
import json
from pathlib import Path
import subprocess
import sys
import tempfile

from compiler_wrapper import expand_wrapper


def cases():
    """Exercises the pinned wrapper's argument and environment transformations."""
    return [
        {"name": "literal-and-continued-inputs", "flags": ["--arg-file", "args", "--env-file", "env"],
         "files": {"args": "literal $(value)\r\ncontinued\\\nnext\npaired\\\\\n\n",
                   "env": "EVIDENCE_VALUE=first=second\nEVIDENCE_MULTILINE=one\\\ntwo\n"}},
        {"name": "repeated-file-groups", "flags": ["--arg-file", "one", "two", "--arg-file", "three",
                                                    "--env-file", "env-one", "env-two"],
         "files": {"one": "first\n", "two": "second\n", "three": "third\n",
                   "env-one": "EVIDENCE_VALUE=old\n", "env-two": "EVIDENCE_VALUE=last\n"}},
        {"name": "workspace-status-order", "flags": ["--env-file", "env", "--stable-status-file", "stable",
                                                      "--volatile-status-file", "volatile"],
         "files": {"env": "EVIDENCE_VALUE={BUILD}:{NEXT}\n", "stable": "BUILD {NEXT}\n", "volatile": "NEXT final\n"}},
        {"name": "execution-roots-and-out-dir", "flags": ["--subst", "pwd=${pwd}", "base=${output_base}",
                                                          "root=${exec_root}", "--out-dir", "bazel-out/generated",
                                                          "--env-file", "env", "--arg-file", "args"],
         "files": {"env": "OUT_DIR=stale\nEVIDENCE_VALUE=${pwd}/${out_dir}/file\n",
                   "args": "${base}/tool\n${root}/source\n${pwd}/input\n"}},
        {"name": "ordered-substitutions", "flags": ["--subst", "one=replaced", "two=${one}", "--arg-file", "args"],
         "files": {"args": "${one}\n${two}\n"}},
        {"name": "explicit-unstable-policy", "flags": ["--require-explicit-unstable-features", "true"], "files": {}},
        {"name": "existing-unstable-allowlist", "flags": ["--require-explicit-unstable-features", "true",
                                                         "--arg-file", "args"],
         "files": {"args": "-Zallow-features=chosen\n"}},
        {"name": "discarded-final-continuation", "flags": ["--arg-file", "args"],
         "files": {"args": "retained\nunterminated\\"}},
    ]


def verify(wrapper, output):
    """Requires the model to match every actual child argument and selected env."""
    results = []
    with tempfile.TemporaryDirectory(prefix="aos-wrapper-evidence-") as temporary:
        base = Path(temporary)
        cwd = base / "execroot/_main"
        cwd.mkdir(parents=True)
        (base / "external").mkdir()
        (cwd / "external").symlink_to(base / "external", target_is_directory=True)
        capture = base / "capture.py"
        capture.write_text(
            "import json, os, sys\n"
            "print(json.dumps({'arguments': sys.argv[1:], 'environment': {\n"
            "    k: v for k, v in os.environ.items() if k.startswith('EVIDENCE_') or k == 'OUT_DIR'}}))\n"
        )
        environment = {"LANG": "C", "LC_ALL": "C", "EVIDENCE_VALUE": "inherited", "EVIDENCE_INHERITED": "kept"}
        roots = {"pwd": str(cwd), "output_base": str(base), "exec_root": str(cwd)}
        for case in cases():
            for name, text in case["files"].items():
                (cwd / name).write_bytes(text.encode("utf-8"))
            command = [str(wrapper), *case["flags"], "--", sys.executable, str(capture), "direct"]
            expected = expand_wrapper(command, environment, case["files"], roots)
            expected["arguments"] = expected["arguments"][2:]
            expected["environment"] = {
                key: value for key, value in expected["environment"].items()
                if key.startswith("EVIDENCE_") or key == "OUT_DIR"
            }
            process = subprocess.run(command, cwd=cwd, env=environment, capture_output=True, text=True, check=True)
            actual = json.loads(process.stdout)
            if actual != expected:
                raise ValueError("pinned Rust wrapper input reconstruction differs: " + case["name"])
            results.append({"name": case["name"], "status": "PASS", "arguments": len(actual["arguments"]),
                            "selected_environment_variables": len(actual["environment"])})
    output.write_text(json.dumps({"schema_version": 1, "status": "PASS", "cases": results}, indent=2) + "\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--wrapper", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    options = parser.parse_args()
    verify(options.wrapper.resolve(), options.output)


if __name__ == "__main__":
    main()
