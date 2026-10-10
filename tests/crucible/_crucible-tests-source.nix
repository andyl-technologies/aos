{lib}:
(import ./_rust-source.nix {
  inherit lib;
  entry = ../../crates/crucible/engine/crucible-engine/src/lib.rs;
  fragmentDirs = [../../crates/crucible/engine/crucible-engine/src/tests];
})
+ builtins.readFile ../../crates/crucible/engine/crucible-engine/src/tests.rs
