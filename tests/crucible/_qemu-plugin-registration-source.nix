{lib}:
import ./_rust-source.nix {
  inherit lib;
  entry = ../../crates/crucible/crucible-qemu-plugin/src/registration.rs;
  fragmentDirs = [../../crates/crucible/crucible-qemu-plugin/src/registration];
}
