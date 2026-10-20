builtins.concatStringsSep "\n" [
  (builtins.readFile ../../crates/crucible/engine/crucible-engine/src/local_backend.rs)
  (builtins.readFile ../../crates/crucible/engine/crucible-engine/src/sim_backend.rs)
  (builtins.readFile ../../crates/crucible/engine/crucible-engine/src/sim_backend/host_schedule.rs)
  (builtins.readFile ../../crates/crucible/engine/crucible-engine/src/sim_backend/shmem.rs)
]
