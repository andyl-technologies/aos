##! Compares selected Rust test and macro profiles with actual Cargo calls.
{
  pkgs,
  pname,
  tests,
  cargo,
  firstPartyTests,
  proceduralMacros,
}: let
  scripts = builtins.path {
    path = ../../tools/bazel/tests;
    name = "aos-bazel-rust-test-profile-verifiers";
    filter = path: type: type == "regular" && pkgs.lib.hasSuffix ".py" path;
  };
in
  pkgs.runCommand pname {buildDeps = [pkgs.python3];} ''
    mkdir -p "$out"
    PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=${scripts} ${pkgs.python3}/bin/python3 - \
      ${tests} ${cargo} \
      ${pkgs.lib.escapeShellArg (builtins.toJSON firstPartyTests)} \
      ${pkgs.lib.escapeShellArg (builtins.toJSON proceduralMacros)} "$out/evidence.json" <<'PYTHON'
    import hashlib
    import json
    from pathlib import Path
    import sys

    from reconstruct_compiler_inputs import reconstruct
    from verify_cache import execution_events
    from verify_compiler_options import compiler_options

    build, cargo = map(Path, sys.argv[1:3])
    targets = json.loads(sys.argv[3])
    required_macros = json.loads(sys.argv[4])
    output = Path(sys.argv[5])
    assert targets and len(set(targets.values())) == len(targets), targets
    assert required_macros and len(set(required_macros)) == len(required_macros), required_macros
    inventory = json.loads((build / "inventory.json").read_text())
    macros = {target["label"]: target["label"].rsplit(":", 1)[1]
              for target in inventory["configured_targets"] if target["kind"] == "rust_proc_macro"}
    assert set(macros.values()) == set(required_macros) and len(macros) == len(required_macros), macros

    def profile(arguments, expected, explicit):
        scalar = compiler_options(arguments)["effective_scalar_codegen"]
        assert scalar.get("opt-level", "0") == expected, scalar
        assert scalar.get("debuginfo", "0") == "0", scalar
        for option in ["debug-assertions", "overflow-checks"]:
            # Rust's unoptimized default enables assertions; overflow checks
            # inherit them. The native profile probe exercises both defaults.
            value = scalar.get(option)
            if value is None and not explicit:
                if option == "debug-assertions":
                    assert expected == "0", scalar
                continue
            assert value in {"yes", "on", "true"}, scalar
        return scalar

    trace = cargo / "compiler-arguments.jsonl"
    cargo_actions = {}
    for line in trace.read_text().splitlines():
        invocation = json.loads(line)
        arguments = invocation["arguments"]
        if any(argument == "--print" or argument.startswith("--print=") for argument in arguments):
            continue
        name = arguments[arguments.index("--crate-name") + 1] if "--crate-name" in arguments else None
        macro = any(left == "--crate-type" and right == "proc-macro"
                    for left, right in zip(arguments, arguments[1:]))
        if not ((macro and name in macros.values()) or ("--test" in arguments and name in targets.values())):
            continue
        assert name not in cargo_actions, name
        cargo_actions[name] = {
            "arguments": arguments,
            "compiler_options": profile(arguments, "0" if macro else "s", False),
        }
    assert set(cargo_actions) == set(macros.values()) | set(targets.values()), cargo_actions.keys()

    evidence = build / "evidence"
    events = execution_events(build)
    actions = reconstruct(
        json.loads((evidence / "actions.json").read_text()), events,
        json.loads((evidence / "compiler-inputs.json").read_text()),
    )["actions"]
    selected = {}
    for action in actions:
        label = action["target_label"]
        if label not in macros.keys() | targets.keys():
            continue
        assert label not in selected, label
        arguments = action["arguments"]
        assert compiler_options(arguments)["test"] == (label in targets), label
        if label in macros:
            assert "--crate-type=proc-macro" in arguments or any(
                left == "--crate-type" and right == "proc-macro"
                for left, right in zip(arguments, arguments[1:])
            ), label
        matching = [event for event in events if event["mnemonic"] == "Rustc" and event["targetLabel"] == label]
        assert len(matching) == 1, matching
        event = matching[0]
        assert event["runner"] == "linux-sandbox" and not event["cacheHit"] and event["exitCode"] == 0
        selected[label] = {
            "compiler_options": profile(arguments, "0" if label in macros else "s", True),
            **{key: event[key] for key in ["runner", "cacheHit", "exitCode"]},
        }
    assert selected.keys() == macros.keys() | targets.keys(), selected.keys()
    output.write_text(json.dumps({
        "schema_version": 1, "status": "PASS", "build": str(build), "cargo": str(cargo),
        "actions": selected, "cargo_actions": cargo_actions,
        "cargo_trace_sha256": hashlib.sha256(trace.read_bytes()).hexdigest(),
        "evidence_sha256": {name: hashlib.sha256((evidence / name).read_bytes()).hexdigest()
                            for name in ["actions.json", "execution.json", "compiler-inputs.json"]},
        "limits": ["Checks selected target and macro profiles, not complete compiler/default, native ABI, linker, editor, production, or performance equivalence."],
    }, indent=2, sort_keys=True) + "\n")
    PYTHON
  ''
