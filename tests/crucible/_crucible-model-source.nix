{lib}:
import ./_rust-source.nix {
  inherit lib;
  entry = ../../crates/crucible/src/model.rs;
  fragmentDirs = [../../crates/crucible/src/model];
}
