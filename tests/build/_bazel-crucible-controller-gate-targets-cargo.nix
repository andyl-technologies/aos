##! Preserves the independent Cargo gate-to-test-target mapping oracle.
{pkgs}:
import ./_bazel-cargo-oracle.nix {
  inherit pkgs;
  pname = "aos-bazel-crucible-controller-gate-targets-cargo-oracle";
  packages = ["crucible-test-support"];
  cargoFlags = ["--test" "gate_target_mapping"];
  captureCompilerArguments = true;
}
