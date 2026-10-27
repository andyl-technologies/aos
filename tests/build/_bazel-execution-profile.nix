##! Executes opposing Rust target and generator profiles in the Nix sandbox.
{pkgs}: let
  flags = checks: [
    "-Copt-level=${
      if checks
      then "0"
      else "3"
    }"
    "-Cdebug-assertions=${
      if checks
      then "yes"
      else "no"
    }"
    "-Coverflow-checks=${
      if checks
      then "yes"
      else "no"
    }"
  ];
  profiles = {
    development = true;
    release = false;
  };
  builds = builtins.mapAttrs (name: executionChecks:
    pkgs.mkAosBazelCheck {
      pname = "aos-bazel-execution-profile-${name}";
      workspace = pkgs.mkAosBazelWorkspace {
        root = ../..;
        sourceDirectories = [
          "tools/bazel/tests/exec-profile"
          "tools/bazel/toolchains"
          "tools/bazel/rules"
          "tools/bazel/metadata"
          "tools/bazel/testing"
        ];
        analysisTargets = ["//tools/bazel/tests/exec-profile:${name}"];
        rustcFlags = flags (!executionChecks);
        execRustcFlags = ["-Copt-level=0"] ++ builtins.tail (flags executionChecks);
      };
      targets = ["//tools/bazel/tests/exec-profile:${name}"];
      testArguments = [
        "--expected-count=3"
        "--require-case=generator_uses_execution_profile"
        "--jobs=1"
      ];
      retainActionGraph = true;
      sharedBuildCache = false;
    })
  profiles;
  scripts = builtins.path {
    path = ../../tools/bazel/tests;
    name = "aos-bazel-execution-profile-verifiers";
    filter = path: type: type == "regular" && pkgs.lib.hasSuffix ".py" path;
  };
  configuration = arguments:
    (pkgs.mkAosBazelWorkspace ({
        root = ../..;
        sourceDirectories = ["tools/bazel/tests/exec-profile"];
      }
      // arguments))
    .configuration.drvPath;
  configurationChecks = {
    empty_execution_flags_preserve_default = configuration {} == configuration {execRustcFlags = [];};
    execution_flags_change_configuration = configuration {} != configuration {execRustcFlags = flags true;};
    invalid_execution_flags_rejected = builtins.all (value:
      !(builtins.tryEval (configuration {execRustcFlags = value;})).success) [
      "not-a-list"
      [""]
      ["-Copt-level=0,-Cpanic=abort"]
      [17]
    ];
  };
  selections = pkgs.writeTextFile {
    name = "execution-profile-builds.json";
    text = builtins.toJSON {
      configuration_checks = configurationChecks;
      profiles =
        builtins.mapAttrs (name: build: {
          path = toString build;
          execution_checks = profiles.${name};
        })
        builds;
    };
  };
in
  assert builtins.all (value: value) (builtins.attrValues configurationChecks);
    pkgs.runCommand "aos-bazel-execution-profile" {buildDeps = [pkgs.python3];} ''
      mkdir -p "$out"
      PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=${scripts} ${pkgs.python3}/bin/python3 - \
        ${selections} "$out/evidence.json" <<'PYTHON'
      import hashlib
      import json
      from pathlib import Path
      import sys
      import xml.etree.ElementTree as ET

      from reconstruct_compiler_inputs import reconstruct
      from verify_cache import execution_events
      from verify_compiler_options import compiler_options

      results = {}
      prefix = "tools/bazel/tests/exec-profile/"
      cases = {"generator_uses_execution_profile", "procedural_macro_uses_execution_profile",
               "target_uses_independent_profile"}
      selections = json.loads(Path(sys.argv[1]).read_text())
      for name, selection in selections["profiles"].items():
          build = Path(selection["path"])
          executions = execution_events(build)
          evidence = build / "evidence"
          actions = reconstruct(
              json.loads((evidence / "actions.json").read_text()), executions,
              json.loads((evidence / "compiler-inputs.json").read_text()),
          )["actions"]
          selected = {}
          for action in actions:
              sources = [arg for arg in action["arguments"] if arg.startswith(prefix) and arg.endswith(".rs")]
              if not sources:
                  continue
              assert len(sources) == 1 and sources[0] not in selected, sources
              source = sources[0]
              target = source.endswith("/test.rs")
              checks = not selection["execution_checks"] if target else selection["execution_checks"]
              scalar = compiler_options(action["arguments"])["effective_scalar_codegen"]
              assert scalar["opt-level"] == ("3" if target and not checks else "0"), scalar
              for option in ["debug-assertions", "overflow-checks"]:
                  assert scalar[option] == ("yes" if checks else "no"), scalar
              matching = [event for event in executions if event["mnemonic"] == "Rustc"
                          and event["targetLabel"] == action["target_label"]]
              assert len(matching) == 1, matching
              assert matching[0]["runner"] == "linux-sandbox" and not matching[0]["cacheHit"]
              assert matching[0]["exitCode"] == 0
              selected[source] = scalar

          assert set(selected) == {prefix + filename for filename in ["generator.rs", "macro.rs", "test.rs"]}
          runners = [event for event in executions if event["mnemonic"] == "TestRunner"]
          assert len(runners) == 1 and runners[0]["runner"] == "linux-sandbox"
          assert not runners[0]["cacheHit"] and runners[0]["exitCode"] == 0
          assert runners[0]["targetLabel"] == "//tools/bazel/tests/exec-profile:" + name
          reports = list((build / "evidence/tests").rglob("test.xml"))
          assert len(reports) == 1
          suite = ET.parse(reports[0]).getroot()
          actual_cases = suite.findall("testcase")
          assert {case.attrib["name"] for case in actual_cases} == cases
          assert len(actual_cases) == 3 and suite.attrib["failures"] == "0"
          assert not any(case.find(tag) is not None for case in actual_cases for tag in ["failure", "error", "skipped"])
          results[name] = {
              **selection, "compiler_options": selected, "cases": sorted(cases),
              "execution_sha256": hashlib.sha256((build / "evidence/execution.json").read_bytes()).hexdigest(),
              "compiler_inputs_sha256": hashlib.sha256((build / "evidence/compiler-inputs.json").read_bytes()).hexdigest(),
          }
      Path(sys.argv[2]).write_text(json.dumps({
          "schema_version": 1, "status": "PASS", "profiles": results,
          "configuration_checks": selections["configuration_checks"],
          "limits": ["Independent execution flag plumbing only; family profile equivalence requires separate qualification."],
      }, indent=2, sort_keys=True) + "\n")
      PYTHON
    ''
