##! Authenticates accache's release and editor procedural-macro profiles.
{
  pkgs,
  production,
  editorWorkspace,
  cargo,
  editorCargoOracle,
}: let
  profiles = {
    release = {
      build = production;
      oracle = cargo;
      opt_level = "0";
    };
    editor = {
      build = pkgs.mkAosBazelBuild {
        pname = "aos-bazel-accache-editor-execution-profile";
        workspace = editorWorkspace;
        targets = ["//crates/accache/accache:accache" "//crates/accache/accache-frontend:lib"];
        retainActionGraph = true;
        sharedBuildCache = false;
      };
      opt_level = "3";
      oracle = editorCargoOracle;
    };
  };
  selections = pkgs.writeTextFile {
    name = "accache-execution-profiles.json";
    text = builtins.toJSON (builtins.mapAttrs (_: profile: {
        path = toString profile.build;
        oracle = toString profile.oracle;
        inherit (profile) opt_level;
      })
      profiles);
  };
  scripts = builtins.path {
    path = ../../tools/bazel/tests;
    name = "aos-bazel-accache-execution-profile-verifiers";
    filter = path: type: type == "regular" && pkgs.lib.hasSuffix ".py" path;
  };
in
  pkgs.runCommand "aos-bazel-accache-execution-profiles" {buildDeps = [pkgs.python3];} ''
    mkdir -p "$out"
    PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=${scripts} ${pkgs.python3}/bin/python3 - \
      ${selections} "$out/evidence.json" <<'PYTHON'
    import hashlib
    import json
    from pathlib import Path
    import sys

    from reconstruct_compiler_inputs import reconstruct
    from verify_cache import execution_events
    from verify_compiler_options import compiler_options

    selections = json.loads(Path(sys.argv[1]).read_text())
    results = {}
    first_party = {"//crates/accache/accache:accache", "//crates/accache/accache-frontend:lib"}
    for name, profile in selections.items():
        build = Path(profile["path"])
        evidence = build / "evidence"
        inventory = json.loads((build / "inventory.json").read_text())
        macros = {target["label"] for target in inventory["configured_targets"]
                  if target["kind"] == "rust_proc_macro"}
        assert macros and any(label.endswith("//:prost_derive") for label in macros), macros
        trace = Path(profile["oracle"]) / "compiler-arguments.jsonl"
        cargo_macros = {}
        for line in trace.read_text().splitlines():
            invocation = json.loads(line)
            arguments = invocation["arguments"]
            if any(argument == "--print" or argument.startswith("--print=") for argument in arguments):
                continue
            if not any(left == "--crate-type" and right == "proc-macro"
                       for left, right in zip(arguments, arguments[1:])):
                continue
            crate_name = arguments[arguments.index("--crate-name") + 1]
            assert crate_name not in cargo_macros, crate_name
            scalar = compiler_options(arguments)["effective_scalar_codegen"]
            assert scalar.get("opt-level", "0") == profile["opt_level"], scalar
            assert scalar.get("debuginfo", "0") == "0", scalar
            assert scalar["strip"] == "symbols", scalar
            assert scalar.get("debug-assertions") in {"no", "off", "false"}, scalar
            if name == "editor":
                assert scalar["overflow-checks"] in {"no", "off", "false"}, scalar
            else:
                # The native Cargo release probe separately exercises the
                # compiler's default overflow behavior with assertions off.
                assert scalar.get("overflow-checks") in {None, "no", "off", "false"}, scalar
            cargo_macros[crate_name] = {"arguments": arguments, "compiler_options": scalar}
        assert set(cargo_macros) == {label.rsplit(":", 1)[1] for label in macros}, cargo_macros.keys()
        events = execution_events(build)
        actions = reconstruct(
            json.loads((evidence / "actions.json").read_text()), events,
            json.loads((evidence / "compiler-inputs.json").read_text()),
        )["actions"]
        selected = {}
        for action in actions:
            label = action["target_label"]
            if label not in macros | first_party:
                continue
            assert label not in selected, label
            arguments = action["arguments"]
            if label in macros:
                assert "--crate-type=proc-macro" in arguments or any(
                    left == "--crate-type" and right == "proc-macro"
                    for left, right in zip(arguments, arguments[1:])
                ), arguments
            scalar = compiler_options(arguments)["effective_scalar_codegen"]
            assert scalar["opt-level"] == (profile["opt_level"] if label in macros else "3"), scalar
            assert scalar["debuginfo"] == "0", scalar
            assert scalar["strip"] == "symbols", scalar
            assert scalar["debug-assertions"] == scalar["overflow-checks"] == "no", scalar
            matching = [event for event in events if event["mnemonic"] == "Rustc"
                        and event["targetLabel"] == label]
            assert len(matching) == 1, matching
            event = matching[0]
            assert event["runner"] == "linux-sandbox" and not event["cacheHit"] and event["exitCode"] == 0
            selected[label] = {"compiler_options": scalar, **{
                key: event[key] for key in ["runner", "cacheHit", "exitCode"]
            }}
        assert selected.keys() == macros | first_party, selected.keys()
        results[name] = {
            **profile, "actions": selected,
            "cargo_macros": cargo_macros,
            "cargo_trace_sha256": hashlib.sha256(trace.read_bytes()).hexdigest(),
            "inputs_sha256": {filename: hashlib.sha256((evidence / filename).read_bytes()).hexdigest()
                              for filename in ["actions.json", "execution.json", "compiler-inputs.json"]},
        }
    Path(sys.argv[2]).write_text(json.dumps({
        "schema_version": 1, "status": "PASS", "profiles": results,
        "limits": [
            "Checks actual macro and first-party compilation profiles, not complete compiler/linker equivalence.",
            "Runtime, test inventory, editor diagnostics, cache integration, production cutover and performance have separate gates.",
        ],
    }, indent=2, sort_keys=True) + "\n")
    PYTHON
  ''
