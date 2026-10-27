##! Rebuilds the migrated GPL artifacts using only the exported repository tree.
{
  sourceArtifact,
  system ? builtins.currentSystem,
  trial ? null,
}: let
  source = builtins.storePath sourceArtifact;
  root = source + "/share/aos/qemu-crucible-source/build/aos";
  aos = import root {inherit system;};
  production = aos.pkgs.callPackage (root + "/pkgs/emulation/_crucible-qemu-bazel.nix") {};
in
  assert trial == null || builtins.match "[a-zA-Z0-9][a-zA-Z0-9_-]*" trial != null; rec {
    # A distinct derivation forces execution from the exported source instead of
    # satisfying this check with the already-realized production build.
    build = aos.pkgs.mkAosBazelBuild {
      pname = "aos-bazel-qemu-gpl-corresponding-source" + aos.lib.optionalString (trial != null) "-${trial}";
      inherit (production) workspace;
      targets = production.productionTargets;
      retainActionGraph = true;
      sharedBuildCache = false;
    };
    installed = aos.pkgs.callPackage (root + "/pkgs/emulation/_crucible-qemu-bazel-installed.nix") {
      inherit build;
    };
  }
