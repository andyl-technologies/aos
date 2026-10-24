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
    selectedCrates = ["crucible/crucible-daemon"];
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
  byDirectory = select {
    root = fixture + "/original";
    sourceDirectories = ["crates/example/src"];
    extraFiles = ["crates/example/BUILD.bazel"];
  };
  byFile = select {
    root = fixture + "/source-added";
    extraFiles = ["crates/example/src/lib.rs" "crates/example/BUILD.bazel"];
  };
  similarPrefix = select {
    root = fixture + "/original";
    sourceDirectories = ["crates/exam"];
  };
in
  assert builtins.pathExists (cargoSource + "/crates/crucible/crucible-daemon/src/executor_worker/result/operations.rs");
  assert original.sourceSelection == "configured-inventory";
  assert original.source == editedDocs.source;
  assert addedSource.source != original.source;
  assert builtins.pathExists (addedSource.source + "/crates/example/src/new.rs");
  assert builtins.pathExists (addedSource.source + "/crates/example/src/result/operations.rs");
  assert !builtins.pathExists (original.source + "/docs");
  assert !builtins.pathExists (original.source + "/target");
  assert byDirectory.source == original.source;
  assert byFile.source == original.source;
  assert !builtins.pathExists (byFile.source + "/crates/example/src/new.rs");
  assert !builtins.pathExists (similarPrefix.source + "/crates/example");
  assert !(builtins.tryEval changedGraph.source).success;
    pkgs.runCommand "aos-bazel-source-selection" {} ''
      mkdir -p "$out"
      printf 'PASS\n' > "$out/result"
    ''
