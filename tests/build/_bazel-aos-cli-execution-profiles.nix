##! Authenticates the CLI generators' independent test, release and editor profiles.
{pkgs}: let
  profiles = {
    test = {
      workspace = (import ./_bazel-aos-cli.nix {inherit pkgs;}).workspace;
      checks = "yes";
      opt_level = "0";
    };
    release = {
      workspace = (import ./_bazel-aos-cli-production.nix {inherit pkgs;}).workspace;
      checks = "no";
      opt_level = "0";
    };
    editor = {
      workspace = (import ./_bazel-aos-cli-editor.nix {inherit pkgs;}).editor-workspace;
      checks = "yes";
      opt_level = "s";
    };
  };
  packages = [
    "crates/packages/aos-build-api"
    "crates/hub/aos-hub-api"
    "crates/hub/aos-hub-service"
  ];
  targets = map (path: "//${path}:build_script") packages;
  builds = builtins.mapAttrs (name: profile:
    pkgs.mkAosBazelBuild {
      pname = "aos-bazel-cli-execution-profile-${name}";
      inherit (profile) workspace;
      inherit targets;
      retainActionGraph = true;
      sharedBuildCache = false;
    })
  profiles;
  selections = pkgs.writeTextFile {
    name = "cli-execution-profile-selections.json";
    text = builtins.toJSON {
      inherit packages;
      profiles =
        builtins.mapAttrs (name: build: {
          path = toString build;
          checks = profiles.${name}.checks;
          opt_level = profiles.${name}.opt_level;
        })
        builds;
    };
  };
  scripts = builtins.path {
    path = ../../tools/bazel/tests;
    name = "aos-bazel-cli-execution-profile-verifiers";
    filter = path: type: type == "regular" && pkgs.lib.hasSuffix ".py" path;
  };
in
  pkgs.runCommand "aos-bazel-cli-execution-profiles" {buildDeps = [pkgs.python3];} ''
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
    expected = {package + "/build.rs" for package in selections["packages"]}
    results = {}
    for name, profile in selections["profiles"].items():
        build = Path(profile["path"])
        evidence = build / "evidence"
        events = execution_events(build)
        actions = reconstruct(
            json.loads((evidence / "actions.json").read_text()), events,
            json.loads((evidence / "compiler-inputs.json").read_text()),
        )["actions"]
        selected = {}
        for action in actions:
            sources = [argument for argument in action["arguments"] if argument in expected]
            if not sources:
                continue
            assert len(sources) == 1 and sources[0] not in selected, sources
            scalar = compiler_options(action["arguments"])["effective_scalar_codegen"]
            assert scalar["opt-level"] == profile["opt_level"] and scalar["debuginfo"] == "0", scalar
            for option in ["debug-assertions", "overflow-checks"]:
                assert scalar[option] == profile["checks"], scalar
            matching = [event for event in events if event["mnemonic"] == "Rustc"
                        and event["targetLabel"] == action["target_label"]]
            assert len(matching) == 1 and matching[0]["exitCode"] == 0
            assert matching[0]["runner"] == "linux-sandbox" and not matching[0]["cacheHit"]
            selected[sources[0]] = scalar
        assert set(selected) == expected, set(selected)
        generator_labels = {"//" + package + ":build_script" for package in selections["packages"]}
        generators = [event for event in events if event["mnemonic"] == "CargoBuildScriptRun"
                      and event["targetLabel"] in generator_labels]
        assert len(generators) == 3 and {event["targetLabel"] for event in generators} == generator_labels
        assert all(event["runner"] == "linux-sandbox" and not event["cacheHit"]
                   and event["exitCode"] == 0 for event in generators)
        results[name] = {
            **profile, "compiler_options": selected,
            "generator_executions": {event["targetLabel"]: {
                key: event[key] for key in ["runner", "cacheHit", "exitCode"]
            } for event in generators},
            "inputs_sha256": {filename: hashlib.sha256((evidence / filename).read_bytes()).hexdigest()
                              for filename in ["actions.json", "execution.json", "compiler-inputs.json"]},
        }
    Path(sys.argv[2]).write_text(json.dumps({
        "schema_version": 1, "status": "PASS", "profiles": results,
        "limits": [
            "Only the three real CLI generators' compiler settings are checked here.",
            "Fleet runtime, editor diagnostics, generated-source parity, complete compiler/linker equivalence, and production cutover require separate qualification.",
        ],
    }, indent=2, sort_keys=True) + "\n")
    PYTHON
  ''
