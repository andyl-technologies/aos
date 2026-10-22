##! Pure checks for generated source contracts; evaluation never runs Bazel.
{pkgs}: let
  select = import ../../pkgs/build-support/_bazel/workspace.nix {
    pkgs = {};
    lib = pkgs.lib;
    modules = {};
    defaultToolchains = null;
    defaultRepositories = {};
  };
  cargoSource = import ../../pkgs/tools/aos/_workspace-source.nix {
    lib = pkgs.lib;
    selectedCrates = ["crucible/control/crucible-daemon"];
  };
  fixture = ../../tools/bazel/tests/source-selection;
  workspace = name:
    select {
      root = fixture + "/${name}";
      sourceInventory = fixture + "/inventory.json";
    };
  original = workspace "original";
  editedDocs = workspace "docs-edited";
  addedSource = workspace "source-added";
  changedGraph = workspace "graph-edited";
in
  assert builtins.pathExists (cargoSource + "/crates/crucible/control/crucible-daemon/src/executor_worker/result/operations.rs");
  assert original.sourceSelection == "configured-inventory";
  assert original.source == editedDocs.source;
  assert addedSource.source != original.source;
  assert builtins.pathExists (addedSource.source + "/crates/example/src/new.rs");
  assert builtins.pathExists (addedSource.source + "/crates/example/src/result/operations.rs");
  assert !builtins.pathExists (original.source + "/docs");
  assert !builtins.pathExists (original.source + "/target");
  assert !(builtins.tryEval changedGraph.source).success;
    pkgs.runCommand "aos-bazel-source-selection" {} ''
      mkdir -p "$out"
      printf 'PASS\n' > "$out/result"
    ''
