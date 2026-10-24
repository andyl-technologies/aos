{lib}:
import ./_rust-source.nix {
  inherit lib;
  entry = ../../crates/crucible/crucible-qemu-shmem/src/lib.rs;
  fragmentDirs = [
    ../../crates/crucible/crucible-qemu-shmem/src/abi_header
    ../../crates/crucible/crucible-qemu-shmem/src/shmem
  ];
}
