##! Executes the static adapter's independently qualified development launchers.
{
  pkgs,
  packages,
  dependencyPackages,
  editor,
  tests,
  cargo,
  editor-builtin-cfg,
}: let
  label = "//crates/activation/aos-activation-crucible";
  scripts = builtins.path {
    path = ../../tools/bazel/tests;
    name = "aos-bazel-activation-crucible-development-verifiers";
    filter = path: type:
      type == "regular" && builtins.elem (baseNameOf path) ["verify_cache.py" "verify_family_editor.py" "verify_protocol.py" "verify_pilot.py"];
  };
in
  pkgs.runCommand "aos-bazel-activation-crucible-development" {buildDeps = [pkgs.python3];} ''
    mkdir -p "$out/editor/evidence" "$out/tests/evidence" "$out/baseline/evidence"
    export AOS_DEV_ROOT=${pkgs.aosBazelActivationCrucibleWorkspace.source}
    export AOS_BAZEL_OUTPUT_BASE="$TMPDIR/tests/bazel"
    ${pkgs.aosBazelActivationCrucibleLauncher}/bin/aos-bazel --nix-sandbox --batch -- \
      test ${label}:unit ${label}:bin_aos-ability-crucible ${label}:doc \
        --build_event_json_file="$out/tests/events.json" \
        --execution_log_json_file="$out/tests/evidence/execution.json"
    ${pkgs.python3}/bin/python3 ${../../tools/bazel/metadata/export_tests.py} \
      --events "$out/tests/events.json" --output "$out/tests/evidence/tests"

    export AOS_DEV_ROOT=${pkgs.aosBazelActivationCrucibleEditorWorkspace.source}
    export AOS_BAZEL_OUTPUT_BASE="$TMPDIR/editor/bazel"
    ${pkgs.aosBazelActivationCrucibleEditorLauncher}/bin/aos-bazel \
      --nix-sandbox --batch --materialize-action-outputs \
      --rust-project-output "$out/editor/rust-project.json" \
      --rust-project-package crates/activation/aos-activation-crucible \
      -- build ${label}:lib ${label}:unit_binary ${label}:aos-ability-crucible \
        ${label}:bin_aos-ability-crucible_binary \
        --execution_log_json_file="$out/editor/evidence/execution.json"
    ln -s ${editor}/execution.json "$out/baseline/evidence/execution.json"
    PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=${scripts} ${pkgs.python3}/bin/python3 - "$out" <<'PYTHON'
    from collections import Counter
    import hashlib
    import json
    from pathlib import Path
    import sys

    from verify_cache import execution_events
    from verify_family_editor import verify
    from verify_protocol import compare

    output = Path(sys.argv[1])
    tests = Path("${tests}")
    cargo = Path("${cargo}")
    packages = ${builtins.toJSON packages}
    parity = compare(output / "tests/evidence/tests", tests / "inventory.json",
                     cargo / "cargo-messages.jsonl", packages, cargo / "cargo-tests.log",
                     dependency_paths=${builtins.toJSON dependencyPackages})
    assert sum(len(target["executed"]) for target in parity["targets"].values()) == 9, parity
    assert all(not target["ignored"] for target in parity["targets"].values()), parity
    results = json.loads((output / "tests/evidence/tests/index.json").read_text())["results"]
    assert results and all(not result["cached_locally"] for result in results), results

    macro_names = {"curve25519_dalek_derive", "ref_cast_impl", "schemars_derive", "serde_derive",
                   "thiserror_impl", "tracing_attributes", "zerocopy_derive"}
    expected = {}
    for event in execution_events(output / "baseline"):
        name = event["targetLabel"].rsplit(":", 1)[-1]
        if event["mnemonic"] != "Rustc" or name not in macro_names:
            continue
        digests = [item["digest"]["hash"] for item in event["actualOutputs"] if item["path"].endswith(".so")]
        assert len(digests) == 1 and name not in expected, event
        expected[name] = digests[0]
    assert set(expected) == macro_names, expected

    project = json.loads((output / "editor/rust-project.json").read_text())
    builtin_cfg = json.loads(Path("${editor-builtin-cfg}/evidence.json").read_text())
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

    graph = verify(project, json.loads((tests / "inventory.json").read_text()), packages,
                   Path("${pkgs.aosBazelActivationCrucibleEditorWorkspace.source}"))
    macros = {crate["display_name"]: hashlib.sha256(Path(crate["proc_macro_dylib_path"]).read_bytes()).hexdigest()
              for crate in project["crates"] if crate["is_proc_macro"]}
    assert macros == expected, (macros, expected)

    runs = {}
    for name in ["tests", "editor"]:
        events = execution_events(output / name)
        assert events and all(event["runner"] == "linux-sandbox" and not event["cacheHit"]
                              and event["exitCode"] == 0 for event in events)
        runs[name] = {"actions": len(events), "mnemonics": dict(Counter(event["mnemonic"] for event in events)),
                      "execution_sha256": hashlib.sha256((output / name / "evidence/execution.json").read_bytes()).hexdigest()}
    (output / "evidence.json").write_text(json.dumps({
        "schema_version": 1, "status": "PASS", "graph": graph, "parity": parity,
        "macro_sha256": macros, "runs": runs,
        "test_launcher": "${pkgs.aosBazelActivationCrucibleLauncher}",
        "editor_launcher": "${pkgs.aosBazelActivationCrucibleEditorLauncher}",
        "test_configuration": "${pkgs.aosBazelActivationCrucibleWorkspace.configuration}",
        "editor_configuration": "${pkgs.aosBazelActivationCrucibleEditorWorkspace.configuration}",
        "qualified_editor": "${editor}",
        "qualified_builtin_cfg": "${editor-builtin-cfg}",
        "builtin_cfg_matches_native": True,
        "limits": [
            "Runs packaged launchers on immutable development snapshots with private batch output bases and no shared action cache.",
            "Both ordinary libtest targets and the empty doctest run. Per-case and feature inventories match the native Cargo oracle with no ignored cases.",
            "Editor roots, features, explicit native cfg and all seven macro artifacts are authenticated; analyzer diagnostics are qualified separately.",
            "The exported project names temporary sandbox paths and is retained as evidence, not a persistent editor configuration.",
        ],
    }, indent=2, sort_keys=True) + "\n")
    PYTHON
  ''
