##! Runs the packaged editor launcher and authenticates its native macro artifacts.
{
  pkgs,
  executionProfiles,
}: let
  scripts = builtins.path {
    path = ../../tools/bazel/tests;
    name = "aos-bazel-accache-development-editor-verifiers";
    filter = path: type: type == "regular" && pkgs.lib.hasSuffix ".py" path;
  };
in
  pkgs.runCommand "aos-bazel-accache-development-editor" {buildDeps = [pkgs.python3];} ''
    mkdir -p "$out"
    export AOS_DEV_ROOT=${pkgs.aosBazelAccacheEditorWorkspace.source}
    export AOS_BAZEL_OUTPUT_BASE="$TMPDIR/bazel"
    ${pkgs.aosBazelAccacheEditorLauncher}/bin/aos-bazel \
      --nix-sandbox --batch --materialize-action-outputs \
      --rust-project-output "$out/rust-project.json" \
      --rust-project-package crates/accache/accache \
      --rust-project-package crates/accache/accache-frontend \
      -- build //crates/accache/accache:accache //crates/accache/accache-frontend:unit_binary \
        --execution_log_json_file="$out/execution.json"
    PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=${scripts} ${pkgs.python3}/bin/python3 - \
      ${executionProfiles}/evidence.json "$out" <<'PYTHON'
    from collections import Counter
    import hashlib
    import json
    from pathlib import Path
    import sys

    from verify_cache import execution_events
    from verify_family_editor import verify

    baseline = json.loads(Path(sys.argv[1]).read_text())
    build = Path(baseline["profiles"]["editor"]["path"])
    output = Path(sys.argv[2])
    expected = {}
    for event in execution_events(build):
        if event["mnemonic"] != "Rustc":
            continue
        name = event["targetLabel"].rsplit(":", 1)[-1]
        if name not in {"serde_derive", "prost_derive"}:
            continue
        artifacts = [entry for entry in event["actualOutputs"] if entry["path"].endswith(".so")]
        assert len(artifacts) == 1 and name not in expected, artifacts
        expected[name] = artifacts[0]["digest"]["hash"]
    assert set(expected) == {"serde_derive", "prost_derive"}, expected

    project = json.loads((output / "rust-project.json").read_text())
    packages = {"accache": "crates/accache/accache", "accache-frontend": "crates/accache/accache-frontend"}
    graph = verify(project, json.loads((build / "inventory.json").read_text()),
                   packages, Path("${pkgs.aosBazelAccacheEditorWorkspace.source}"))
    actual = {}
    for crate in project["crates"]:
        if not crate["is_proc_macro"]:
            continue
        name = crate["display_name"]
        assert name in expected and name not in actual, name
        actual[name] = hashlib.sha256(Path(crate["proc_macro_dylib_path"]).read_bytes()).hexdigest()
    assert actual == expected, (actual, expected)

    # Reuse the execution stream reader without changing the launcher's output
    # layout. No compiler cache is supplied to this packaged launcher run.
    (output / "evidence").mkdir()
    (output / "evidence/execution.json").symlink_to("../execution.json")
    events = execution_events(output)
    assert events and all(event["runner"] == "linux-sandbox" and not event["cacheHit"]
                          and event["exitCode"] == 0 for event in events)
    (output / "evidence.json").write_text(json.dumps({
        "schema_version": 1, "status": "PASS", "graph": graph,
        "macro_sha256": actual, "qualified_execution_profiles": str(Path(sys.argv[1]).parent),
        "launcher": "${pkgs.aosBazelAccacheEditorLauncher}",
        "actions": len(events), "mnemonics": dict(Counter(event["mnemonic"] for event in events)),
        "cache_hits": 0, "runner": "linux-sandbox",
        "execution_sha256": hashlib.sha256((output / "execution.json").read_bytes()).hexdigest(),
        "limits": [
            "Runs the packaged launcher on an immutable development snapshot with a private batch output base.",
            "Authenticates exported roots, features and macro bytes; full analyzer diagnostics are qualified separately.",
            "The temporary sandbox output base is removed after the check. This exported project is evidence, not a persistent editor configuration.",
        ],
    }, indent=2, sort_keys=True) + "\n")
    PYTHON
  ''
