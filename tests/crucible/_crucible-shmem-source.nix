{lib}:
import ./_rust-source.nix {
  inherit lib;
  entry = ../../crates/crucible-shmem/src/lib.rs;
  fragmentDirs = [
    ../../crates/crucible-shmem/src/abi_header
    ../../crates/crucible-shmem/src/shmem
  ];
}
