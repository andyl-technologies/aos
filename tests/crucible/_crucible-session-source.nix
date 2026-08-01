{lib}:
import ./_rust-source.nix {
  inherit lib;
  entry = ../../crates/crucible-session/src/lib.rs;
  fragmentDirs = [../../crates/crucible-session/src];
}
