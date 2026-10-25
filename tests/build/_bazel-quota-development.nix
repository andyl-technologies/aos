##! Executes the quota development launchers with their qualified profiles.
{
  pkgs,
  editor,
  tests,
  editorBuiltinCfg,
}: let
  scripts = builtins.path {
    path = ../../tools/bazel/tests;
    name = "aos-bazel-quota-development-verifiers";
    filter = path: type:
      type == "regular" && builtins.elem (baseNameOf path) ["verify_cache.py" "verify_family_editor.py"];
  };
in
  pkgs.runCommand "aos-bazel-quota-development" {buildDeps = [pkgs.python3];} ''
    mkdir -p "$out/editor/evidence" "$out/tests/evidence" "$out/baseline/evidence"
    export AOS_DEV_ROOT=${pkgs.aosBazelQuotaWorkspace.source}
    export AOS_BAZEL_OUTPUT_BASE="$TMPDIR/tests"
    ${pkgs.aosBazelQuotaLauncher}/bin/aos-bazel --nix-sandbox --batch -- \
      test //crates/linux/aos-linux-project-quota:unit \
      --test_arg=--expected-count=8 --test_arg=--jobs=1 \
      --execution_log_json_file="$out/tests/evidence/execution.json"

    export AOS_DEV_ROOT=${pkgs.aosBazelQuotaEditorWorkspace.source}
    export AOS_BAZEL_OUTPUT_BASE="$TMPDIR/editor"
    ${pkgs.aosBazelQuotaEditorLauncher}/bin/aos-bazel \
      --nix-sandbox --batch --materialize-action-outputs \
      --rust-project-output "$out/editor/rust-project.json" \
      --rust-project-package crates/linux/aos-linux-project-quota \
      -- build //crates/linux/aos-linux-project-quota:unit_binary \
        //crates/linux/aos-linux-project-quota:project-quota-flight \
        --execution_log_json_file="$out/editor/evidence/execution.json"
    ln -s ${editor}/execution.json "$out/baseline/evidence/execution.json"
    PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=${scripts} ${pkgs.python3}/bin/python3 - "$out" ${editorBuiltinCfg}/evidence.json <<'PYTHON'
    from collections import Counter
    import hashlib
    import json
    from pathlib import Path
    import sys

    from verify_cache import execution_events
    from verify_family_editor import verify

    output = Path(sys.argv[1])
    expected = []
    for event in execution_events(output / "baseline"):
        if event["mnemonic"] == "Rustc" and event["targetLabel"].endswith(":thiserror_impl"):
            expected.extend(item["digest"]["hash"] for item in event["actualOutputs"] if item["path"].endswith(".so"))
    assert len(expected) == 1, expected
    project = json.loads((output / "editor/rust-project.json").read_text())
    builtin_cfg = json.loads(Path(sys.argv[2]).read_text())
    assert builtin_cfg["status"] == "PASS"
    cfgs = builtin_cfg["native_cfg"]
    names = ({cfg.partition("=")[0] for cfg in cfgs}
             - {"feature", "test", "rust_analyzer", "proc_macro"}) | {"debug_assertions"}
    for crate in project["crates"]:
        actual_cfg = sorted(cfg for cfg in crate["cfg"]
                            if cfg.partition("=")[0] in names or cfg.startswith("target_"))
        assert actual_cfg == cfgs, (crate["root_module"], actual_cfg, cfgs)
        if crate["is_workspace_member"]:
            assert "rust_analyzer" in crate["cfg"], crate

    graph = verify(project, json.loads(Path("${tests}/inventory.json").read_text()),
                   {"aos-linux-project-quota": "crates/linux/aos-linux-project-quota"},
                   Path("${pkgs.aosBazelQuotaEditorWorkspace.source}"))
    macros = {crate["display_name"]: hashlib.sha256(Path(crate["proc_macro_dylib_path"]).read_bytes()).hexdigest()
              for crate in project["crates"] if crate["is_proc_macro"]}
    assert macros == {"thiserror_impl": expected[0]}, macros

    runs = {}
    for name in ["tests", "editor"]:
        events = execution_events(output / name)
        assert events and all(event["runner"] == "linux-sandbox" and not event["cacheHit"]
                              and event["exitCode"] == 0 for event in events)
        runs[name] = {"actions": len(events), "mnemonics": dict(Counter(event["mnemonic"] for event in events)),
                      "execution_sha256": hashlib.sha256((output / name / "evidence/execution.json").read_bytes()).hexdigest()}
    (output / "evidence.json").write_text(json.dumps({
        "schema_version": 1, "status": "PASS", "graph": graph,
        "macro_sha256": macros, "runs": runs,
        "test_launcher": "${pkgs.aosBazelQuotaLauncher}",
        "editor_launcher": "${pkgs.aosBazelQuotaEditorLauncher}",
        "test_configuration": "${pkgs.aosBazelQuotaWorkspace.configuration}",
        "editor_configuration": "${pkgs.aosBazelQuotaEditorWorkspace.configuration}",
        "qualified_editor": "${editor}",
        "qualified_builtin_cfg": str(Path(sys.argv[2]).parent),
        "builtin_cfg_matches_native": True,
        "limits": [
            "Runs packaged launchers on immutable development snapshots with private batch output bases and no shared action cache.",
            "Eight ordinary unit cases run. Exported editor roots, features and macro bytes are authenticated; full analyzer diagnostics are qualified separately.",
            "The exported project names temporary sandbox paths and is retained as evidence, not a persistent editor configuration.",
        ],
    }, indent=2, sort_keys=True) + "\n")
    PYTHON
  ''
