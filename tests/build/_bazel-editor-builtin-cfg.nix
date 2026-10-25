##! Compares exported built-in cfgs with the native analyzer's actual query.
{
  pkgs,
  pname,
  editor,
  cargo,
  workspace,
  flags,
}: let
  adapter = ../../tools/bazel/metadata/editor_cfg.py;
  configuration = arguments:
    (pkgs.mkAosBazelWorkspace ({
        root = ../..;
        sourceDirectories = ["tools/bazel/tests/fixture"];
      }
      // arguments))
    .configuration.drvPath;
  configurationChecks = {
    default_exporter_preserved = configuration {} == configuration {editorCfgFlags = null;};
    explicit_cfg_query_changes_configuration = configuration {} != configuration {editorCfgFlags = [];};
    foreign_target_cfg_rejected =
      !(builtins.tryEval (configuration {
        editorCfgFlags = [];
        targetPlatform = "//tools/bazel/toolchains:aarch64-linux";
      }))
      .success;
    invalid_cfg_flags_rejected = builtins.all (value:
      !(builtins.tryEval (configuration {editorCfgFlags = value;})).success) [
      "not-a-list"
      [""]
      ["-Copt-level=0,-Cpanic=abort"]
      [17]
    ];
  };
in
  assert builtins.all (value: value) (builtins.attrValues configurationChecks);
    pkgs.runCommand pname {buildDeps = [pkgs.python3];} ''
      mkdir -p "$out"
      PYTHONDONTWRITEBYTECODE=1 ${pkgs.python3}/bin/python3 - \
        ${adapter} ${editor}/rust-project.json ${cargo}/compiler-arguments.jsonl \
        ${workspace.toolchains}/bin/rustc \
        ${pkgs.lib.escapeShellArg pkgs.stdenv.hostPlatform.config} \
        ${pkgs.lib.escapeShellArg (builtins.toJSON flags)} "$out/evidence.json" \
        ${pkgs.lib.escapeShellArg (builtins.toJSON configurationChecks)} <<'PYTHON'
      import hashlib
      import importlib.util
      import json
      from pathlib import Path
      import subprocess
      import sys

      adapter, project, trace, compiler, target = sys.argv[1:6]
      flags = json.loads(sys.argv[6])
      output = Path(sys.argv[7])
      specification = importlib.util.spec_from_file_location("editor_cfg", adapter)
      module = importlib.util.module_from_spec(specification)
      specification.loader.exec_module(module)
      query = module.compiler_cfg(compiler, target, flags)

      calls = [json.loads(line)["arguments"] for line in Path(trace).read_text().splitlines()]
      native = [arguments for arguments in calls
                if "--print" in arguments and arguments[arguments.index("--print") + 1] == "cfg"]
      assert len(native) == 1 and native[0][0] == compiler, native
      native_cfg = sorted(subprocess.check_output(native[0], text=True).splitlines())
      assert query["cfg"] == native_cfg, (query, native_cfg)

      project = Path(project)
      crates = json.loads(project.read_text())["crates"]
      names = ({cfg.partition("=")[0] for cfg in native_cfg}
               - {"feature", "test", "rust_analyzer", "proc_macro"}) | {"debug_assertions"}
      selected = {}
      for index, crate in enumerate(crates):
          actual = sorted(cfg for cfg in crate["cfg"]
                          if cfg.partition("=")[0] in names or cfg.startswith("target_"))
          assert actual == native_cfg, (crate["root_module"], actual, native_cfg)
          if crate["is_workspace_member"]:
              assert "rust_analyzer" in crate["cfg"], crate
              selected[str(index)] = {"root": crate["root_module"], "cfg": crate["cfg"]}
      assert selected, "editor cfg audit selected no first-party roots"

      output.write_text(json.dumps({
          "schema_version": 1, "status": "PASS", "editor": "${editor}", "cargo": "${cargo}",
          "configuration_checks": json.loads(sys.argv[8]),
          "compiler_query": query, "native_query": native[0], "native_cfg": native_cfg,
          "configured_crates": len(crates), "selected_roots": selected,
          "project_sha256": hashlib.sha256(project.read_bytes()).hexdigest(),
          "native_trace_sha256": hashlib.sha256(Path(trace).read_bytes()).hexdigest(),
          "limits": [
              "Compares explicit exported built-in cfg fields with the actual native analyzer query; feature, test, graph and diagnostic parity remain independent checks.",
              "The native target cfg query is independent of host macro compilation. This does not qualify execution-tool compiler defaults or a foreign target.",
          ],
      }, indent=2, sort_keys=True) + "\n")
      PYTHON
    ''
