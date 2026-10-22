{lib}:
import ./_rust-source.nix {
  inherit lib;
  entry = ../../crates/crucible/crucible-engine/src/scheduler.rs;
  fragmentDirs = [../../crates/crucible/crucible-engine/src/scheduler];
}
