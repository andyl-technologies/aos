{lib}:
import ./_rust-source.nix {
  inherit lib;
  entry = ../../crates/crucible-qemu-plugin/src/registration.rs;
  fragmentDirs = [../../crates/crucible-qemu-plugin/src/registration];
}
