{lib}:
import ./_rust-source.nix {
  inherit lib;
  entry = ../../crates/crucible/src/scheduler.rs;
  fragmentDirs = [../../crates/crucible/src/scheduler];
}
