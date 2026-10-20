{lib}:
import ./_rust-source.nix {
  inherit lib;
  entry = ../../crates/crucible/protocol/crucible-qemu-shmem/src/lib.rs;
  fragmentDirs = [
    ../../crates/crucible/protocol/crucible-qemu-shmem/src/abi_header
    ../../crates/crucible/protocol/crucible-qemu-shmem/src/shmem
  ];
}
