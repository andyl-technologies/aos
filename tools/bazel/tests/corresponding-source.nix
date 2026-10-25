##! Rebuilds the migrated GPL artifacts using only the exported repository tree.
{
  sourceArtifact,
  system ? builtins.currentSystem,
}: let
  source = builtins.storePath sourceArtifact;
  root = source + "/share/aos/qemu-crucible-source/build/aos";
  aos = import root {inherit system;};
  qualification = aos.checks.build.bazel.qemu-gpl;
in rec {
  # A distinct derivation forces execution from the exported source instead of
  # satisfying this check with the already-realized production build.
  build = aos.pkgs.mkAosBazelBuild {
    pname = "aos-bazel-qemu-gpl-corresponding-source";
    inherit (qualification) workspace;
    targets = qualification.productionTargets;
    retainActionGraph = true;
    sharedBuildCache = false;
  };
  installed = import (root + "/tests/build/_bazel-qemu-gpl-installed.nix") {
    pkgs = aos.pkgs;
    inherit build;
  };
}
