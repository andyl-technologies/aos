{lib}:
import ./_rust-source.nix {
  inherit lib;
  entry = ../../crates/crucible/engine/crucible-engine/src/model.rs;
  fragmentDirs = [../../crates/crucible/engine/crucible-engine/src/model];
}
