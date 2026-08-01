{lib}:
(import ./_rust-source.nix {
  inherit lib;
  entry = ../../crates/crucible/src/lib.rs;
  fragmentDirs = [../../crates/crucible/src/tests];
})
+ builtins.readFile ../../crates/crucible/src/tests.rs
