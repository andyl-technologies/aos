{lib}:
(import ./_rust-source.nix {
  inherit lib;
  entry = ../../crates/crucible/crucible-engine/src/lib.rs;
  fragmentDirs = [../../crates/crucible/crucible-engine/src/tests];
})
+ builtins.readFile ../../crates/crucible/crucible-engine/src/tests.rs
