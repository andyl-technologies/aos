{lib}:
import ./_rust-source.nix {
  inherit lib;
  entry = ../../crates/crucible/engine/crucible-engine/src/scheduler.rs;
  fragmentDirs = [../../crates/crucible/engine/crucible-engine/src/scheduler];
}
