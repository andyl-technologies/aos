##! Compares actual native analyzer macro compilations with retained Bazel actions.
{
  pkgs,
  pname,
  editor,
  cargo,
  proceduralMacros,
}: let
  scripts = builtins.path {
    path = ../../tools/bazel/tests;
    name = "aos-bazel-editor-profile-verifiers";
    filter = path: type: type == "regular" && pkgs.lib.hasSuffix ".py" path;
  };
in
  pkgs.runCommand pname {buildDeps = [pkgs.python3];} ''
    mkdir -p "$out"
    PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=${scripts} ${pkgs.python3}/bin/python3 - \
      ${editor} ${cargo}/compiler-arguments.jsonl \
      ${pkgs.lib.escapeShellArg (builtins.toJSON proceduralMacros)} "$out/evidence.json" <<'PYTHON'
    import hashlib
    import json
    from pathlib import Path
    import sys

    from reconstruct_compiler_inputs import reconstruct
    from verify_cache import execution_events
    from verify_compiler_options import compiler_options

    editor, trace = map(Path, sys.argv[1:3])
    expected = json.loads(sys.argv[3])
    assert expected and len(expected) == len(set(expected))

    def crate_name(arguments):
        names = [argument.partition("=")[2] for argument in arguments
                 if argument.startswith("--crate-name=")]
        names.extend(right for left, right in zip(arguments, arguments[1:]) if left == "--crate-name")
        assert len(names) == 1 and names[0], names
        return names[0]

    def profile(arguments, explicit):
        options = compiler_options(arguments)
        scalar = options["effective_scalar_codegen"]
        assert scalar.get("opt-level", "0") == "0", scalar
        assert scalar.get("debuginfo", "0") == "2", scalar
        assert scalar.get("strip", "none") == "none", scalar
        for name in ["debug-assertions", "overflow-checks"]:
            # Unoptimized native compilation enables assertions and overflow
            # checks by default; preserve absent flags in the retained evidence.
            assert scalar.get(name) in ({"yes", "on", "true"} if explicit else {None, "yes", "on", "true"}), scalar
        assert not any(flag.startswith(("target-feature=", "relocation-model="))
                       for flag in options["codegen"]), options
        return scalar

    native = {}
    for line in trace.read_text().splitlines():
        arguments = json.loads(line)["arguments"]
        if any(argument == "--print" or argument.startswith("--print=") for argument in arguments):
            continue
        if not any(left == "--crate-type" and right == "proc-macro"
                   for left, right in zip(arguments, arguments[1:])):
            continue
        name = crate_name(arguments)
        assert name not in native, name
        native[name] = {"arguments": arguments, "scalar": profile(arguments, False)}
    assert set(native) == set(expected), native.keys()

    evidence = editor / "evidence"
    events = execution_events(editor)
    actions = reconstruct(json.loads((evidence / "actions.json").read_text()), events,
                          json.loads((evidence / "compiler-inputs.json").read_text()))["actions"]
    selected = {}
    for action in actions:
        arguments = action["arguments"]
        if not ("--crate-type=proc-macro" in arguments or any(
                left == "--crate-type" and right == "proc-macro"
                for left, right in zip(arguments, arguments[1:]))):
            continue
        name = crate_name(arguments)
        assert name not in selected, name
        matching = [event for event in events if event["mnemonic"] == "Rustc"
                    and event["targetLabel"] == action["target_label"]]
        assert len(matching) == 1, matching
        event = matching[0]
        assert event["runner"] == "linux-sandbox" and not event["cacheHit"] and event["exitCode"] == 0
        selected[name] = {"target_label": action["target_label"], "scalar": profile(arguments, True),
                          "runner": event["runner"], "cache_hit": event["cacheHit"]}
    assert set(selected) == set(expected), selected.keys()
    Path(sys.argv[4]).write_text(json.dumps({
        "schema_version": 1, "status": "PASS", "editor": str(editor),
        "native_macros": native, "bazel_macros": selected,
        "native_trace_sha256": hashlib.sha256(trace.read_bytes()).hexdigest(),
        "evidence_sha256": {name: hashlib.sha256((evidence / name).read_bytes()).hexdigest()
                            for name in ["actions.json", "execution.json", "compiler-inputs.json"]},
        "limits": ["Checks selected native development macros at optimization 0, debug information 2 and enabled checks. Complete compiler defaults, ABI/linker equivalence, other profiles and foreign targets remain separate."],
    }, indent=2, sort_keys=True) + "\n")
    PYTHON
  ''
