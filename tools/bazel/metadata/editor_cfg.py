"""Derives editor built-in cfgs from the declared native analyzer profile.

The configured aspect still owns roots, dependency identities, features,
generated inputs and macro artifacts. This adapter replaces its historical
unconditional debug-assertion cfg with the source-built compiler's answer.
"""

import argparse
import copy
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile


def compiler_cfg(compiler, target, flags):
    """Queries built-in cfgs in the order used by the native analyzer."""
    if not Path(compiler).is_absolute() or not target:
        raise ValueError("editor cfg requires an absolute compiler and target")

    # The native Cargo model queries an optimized target independently of the
    # development profile used to compile its generators and macro dylibs.
    arguments = [str(compiler), *flags, "-O", "--target", target, "--print", "cfg"]
    result = subprocess.run(arguments, check=True, capture_output=True, text=True)
    cfgs = result.stdout.splitlines()
    syntax = re.compile(r'[A-Za-z_][A-Za-z_0-9]*(?:="(?:[^"\\]|\\.)*")?')
    if not cfgs or any(not syntax.fullmatch(cfg) for cfg in cfgs):
        raise ValueError("compiler returned malformed editor cfgs")
    if len(set(cfgs)) != len(cfgs) or not any(cfg.startswith("target_arch=") for cfg in cfgs):
        raise ValueError("compiler returned incomplete or duplicate editor cfgs")
    return {"arguments": arguments, "cfg": sorted(cfgs)}


def apply_cfg(project, cfgs, workspace):
    """Preserves the configured graph while replacing built-in cfg assumptions."""
    result = copy.deepcopy(project)
    workspace = Path(workspace).resolve()
    if not result.get("crates"):
        raise ValueError("editor project has no configured crates")
    builtin_names = ({cfg.partition("=")[0] for cfg in cfgs}
                     - {"feature", "test", "rust_analyzer", "proc_macro"}) | {"debug_assertions"}

    for crate in result["crates"]:
        existing = crate["cfg"]
        if not isinstance(existing, list) or any(not isinstance(cfg, str) for cfg in existing):
            raise ValueError("editor crate has invalid cfg metadata")
        # Current native application crates inherit their compiler cfg query.
        # The aspect's unconditional debug_assertions predates that behavior.
        selected = {cfg for cfg in existing
                    if cfg.partition("=")[0] not in builtin_names and not cfg.startswith("target_")}
        selected.update(cfgs)
        if Path(crate["root_module"]).is_relative_to(workspace):
            selected.add("rust_analyzer")
        crate["cfg"] = sorted(selected)
    return result


def main(exporter, compiler, target, flags):
    """Exports the configured graph and publishes corrected metadata atomically."""
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--workspace", type=Path, required=True)
    options, _ = parser.parse_known_args()
    query = compiler_cfg(compiler, target, flags)

    output = options.output.resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".aos-editor-cfg-", dir=output.parent) as scratch:
        temporary = Path(scratch) / "rust-project.json"
        # The base export must complete before any metadata reaches the editor.
        subprocess.run([sys.executable, str(exporter), *sys.argv[1:], "--output", str(temporary)], check=True)
        project = json.loads(temporary.read_text())
        updated = apply_cfg(project, query["cfg"], options.workspace)
        temporary.write_text(json.dumps(updated, indent=2) + "\n")
        temporary.replace(output)
