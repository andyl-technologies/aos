##! Preserves the independent Cargo dependency and scheduler audit oracle.
{pkgs}:
import ./_bazel-cargo-oracle.nix {
  inherit pkgs;
  pname = "aos-bazel-crucible-controller-dependency-cargo-oracle";
  packages = ["crucible-test-support"];
  cargoFlags = ["--test" "harness_components" "--test" "standalone_dependencies" "--test" "single_scheduler_boundary"];
  captureCompilerArguments = true;
}
