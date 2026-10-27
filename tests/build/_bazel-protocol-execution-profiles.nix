##! Authenticates the protocol graph's target and execution test profiles.
{
  pkgs,
  tests,
  cargo,
}:
import ./_bazel-rust-test-profiles.nix {
  inherit pkgs tests cargo;
  pname = "aos-bazel-protocol-execution-profiles";
  firstPartyTests = {
    "//crates/crucible/crucible-qemu-protocol:unit_binary" = "crucible_qemu_protocol";
    "//crates/crucible/crucible-qemu-shmem:unit_binary" = "crucible_qemu_shmem";
  };
  proceduralMacros = ["serde_derive" "thiserror_impl"];
}
