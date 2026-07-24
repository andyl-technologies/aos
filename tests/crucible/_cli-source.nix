{lib}: let
  tree = import ./_rust-source.nix {
    inherit lib;
    entry = ../../crates/crucible-cli/src/main.rs;
    fragmentDirs = [
      ../../crates/crucible-cli/src/cli
      ../../crates/crucible-cli/src/tests
    ];
  };
in
  tree + builtins.readFile ../../crates/crucible-cli/src/tests.rs
