{lib}:
import ./_rust-source.nix {
  inherit lib;
  entry = ../../crates/crucible/qemu/crucible-qemu-plugin/src/setup.rs;
  fragmentDirs = [../../crates/crucible/qemu/crucible-qemu-plugin/src/setup];
}
