builtins.concatStringsSep "\n" [
  (builtins.readFile ../../crates/crucible/src/local_backend.rs)
  (builtins.readFile ../../crates/crucible/src/sim_backend.rs)
  (builtins.readFile ../../crates/crucible/src/sim_backend/host_schedule.rs)
  (builtins.readFile ../../crates/crucible/src/sim_backend/shmem.rs)
]
