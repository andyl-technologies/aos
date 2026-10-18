{lib}:
import ./_rust-source.nix {
  inherit lib;
  entry = ../../crates/crucible/control/crucible-session/src/lib.rs;
  fragmentDirs = [../../crates/crucible/control/crucible-session/src];
}
