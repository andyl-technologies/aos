##! Executes the guest development launchers with independently qualified profiles.
{
  pkgs,
  editor,
  tests,
  cargo,
  editor-builtin-cfg,
}: let
  label = "//crates/crucible/crucible-guest";
  scripts = builtins.path {
    path = ../../tools/bazel/tests;
    name = "aos-bazel-guest-development-verifiers";
    filter = path: type:
      type == "regular" && builtins.elem (baseNameOf path) ["verify_cache.py" "verify_family_editor.py" "verify_protocol.py" "verify_pilot.py"];
  };
in
  pkgs.runCommand "aos-bazel-guest-development" {buildDeps = [pkgs.python3];} ''
    mkdir -p "$out/editor/evidence" "$out/tests/evidence" "$out/baseline/evidence"
    export AOS_DEV_ROOT=${pkgs.aosBazelGuestWorkspace.source}
    export AOS_BAZEL_OUTPUT_BASE="$TMPDIR/tests/bazel"
    ${pkgs.aosBazelGuestLauncher}/bin/aos-bazel --nix-sandbox --batch -- \
      test ${label}:unit ${label}:bin_crucible-guest \
        ${label}:gate_abi_conformance ${label}:gate_single_vm_fingerprint ${label}:doc \
        --build_event_json_file="$out/tests/events.json" \
        --execution_log_json_file="$out/tests/evidence/execution.json"
    ${pkgs.python3}/bin/python3 ${../../tools/bazel/metadata/export_tests.py} \
      --events "$out/tests/events.json" --output "$out/tests/evidence/tests"

    export AOS_DEV_ROOT=${pkgs.aosBazelGuestEditorWorkspace.source}
    export AOS_BAZEL_OUTPUT_BASE="$TMPDIR/editor/bazel"
    ${pkgs.aosBazelGuestEditorLauncher}/bin/aos-bazel \
      --nix-sandbox --batch --materialize-action-outputs \
      --rust-project-output "$out/editor/rust-project.json" \
      --rust-project-package crates/crucible/crucible-guest \
      -- build ${label}:lib ${label}:unit_binary ${label}:crucible-guest \
        ${label}:bin_crucible-guest_binary ${label}:gate_abi_conformance_binary \
        ${label}:gate_single_vm_fingerprint_binary \
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
    package = {"crucible-guest": "crates/crucible/crucible-guest"}
    parity = compare(output / "tests/evidence/tests", tests / "inventory.json",
                     cargo / "cargo-messages.jsonl", package, cargo / "cargo-tests.log",
                     dependency_paths={name: "crates/crucible/" + name for name in [
                         "crucible-qemu-protocol", "crucible-campaign", "crucible-store"]})
    assert sum(len(target["executed"]) for target in parity["targets"].values()) == 33, parity
    assert sum(len(target["ignored"]) for target in parity["targets"].values()) == 1, parity
    results = json.loads((output / "tests/evidence/tests/index.json").read_text())["results"]
    assert results and all(not result["cached_locally"] for result in results), results

    expected = {}
    for event in execution_events(output / "baseline"):
        name = event["targetLabel"].rsplit(":", 1)[-1]
        if event["mnemonic"] != "Rustc" or name not in {"curve25519_dalek_derive", "serde_derive", "thiserror_impl"}:
            continue
        digests = [item["digest"]["hash"] for item in event["actualOutputs"] if item["path"].endswith(".so")]
        assert len(digests) == 1 and name not in expected, event
        expected[name] = digests[0]
    assert set(expected) == {"curve25519_dalek_derive", "serde_derive", "thiserror_impl"}, expected

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

    graph = verify(project, json.loads((tests / "inventory.json").read_text()), package,
                   Path("${pkgs.aosBazelGuestEditorWorkspace.source}"))
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
        "test_launcher": "${pkgs.aosBazelGuestLauncher}",
        "editor_launcher": "${pkgs.aosBazelGuestEditorLauncher}",
        "test_configuration": "${pkgs.aosBazelGuestWorkspace.configuration}",
        "editor_configuration": "${pkgs.aosBazelGuestEditorWorkspace.configuration}",
        "qualified_editor": "${editor}",
        "qualified_builtin_cfg": "${editor-builtin-cfg}",
        "builtin_cfg_matches_native": True,
        "limits": [
            "Runs packaged launchers on immutable development snapshots with private batch output bases and no shared action cache.",
            "All four ordinary libtest targets and the doctest run. Per-case inventories, features and ignored cases match the native Cargo oracle.",
            "Editor roots, features, explicit native cfg and macro bytes are authenticated; analyzer diagnostics are qualified separately.",
            "The exported project names temporary sandbox paths and is retained as evidence, not a persistent editor configuration.",
        ],
    }, indent=2, sort_keys=True) + "\n")
    PYTHON
  ''
