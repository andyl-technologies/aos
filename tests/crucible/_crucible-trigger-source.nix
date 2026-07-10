{lib}:
import ./_rust-source.nix {
  inherit lib;
  entry = ../../crates/crucible/src/trigger.rs;
  fragmentDirs = [../../crates/crucible/src/trigger];
}
