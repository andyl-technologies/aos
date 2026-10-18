{lib}: let
  tree = import ./_rust-source.nix {
    inherit lib;
    entry = ../../crates/crucible/control/crucible-cli/src/main.rs;
    fragmentDirs = [
      ../../crates/crucible/control/crucible-cli/src/cli
      ../../crates/crucible/control/crucible-cli/src/tests
    ];
  };
in
  tree + builtins.readFile ../../crates/crucible/control/crucible-cli/src/tests.rs
