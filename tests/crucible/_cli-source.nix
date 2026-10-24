{lib}: let
  tree = import ./_rust-source.nix {
    inherit lib;
    entry = ../../crates/crucible/crucible-cli/src/main.rs;
    fragmentDirs = [
      ../../crates/crucible/crucible-cli/src/cli
      ../../crates/crucible/crucible-cli/src/tests
    ];
  };
in
  tree + builtins.readFile ../../crates/crucible/crucible-cli/src/tests.rs
