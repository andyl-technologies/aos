builtins.concatStringsSep "\n" [
  (builtins.readFile ../../crates/crucible/src/local_backend.rs)
  (builtins.readFile ../../crates/crucible/src/sim_backend.rs)
]
