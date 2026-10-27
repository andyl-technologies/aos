{lib}:
import ./_rust-source.nix {
  inherit lib;
  entry = ../../crates/crucible/crucible-session/src/lib.rs;
  fragmentDirs = [../../crates/crucible/crucible-session/src];
}
