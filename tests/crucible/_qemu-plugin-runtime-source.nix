{lib}:
import ./_rust-source.nix {
  inherit lib;
  entry = ../../crates/crucible/qemu/crucible-qemu-plugin/src/runtime.rs;
  fragmentDirs = [../../crates/crucible/qemu/crucible-qemu-plugin/src/runtime];
}
