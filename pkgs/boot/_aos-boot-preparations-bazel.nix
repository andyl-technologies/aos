##! Preserves the standalone initrd package while Bazel owns compilation and tests.
{
  rustcPackage,
  callPackage,
  mkAosBazelPackage,
  stdenv,
  sourceInventory ? ../../tools/bazel/metadata/initrd-preparation-inventory.json,
}: let
  prefix = "//crates/boot/aos-boot-runtime:";
  build = callPackage ./_aos-boot-preparations-bazel-build.nix {inherit sourceInventory;};
  workspace = build.passthru.bazelSelection.workspace;
  package = mkAosBazelPackage {
    # The declared Rust package owns the payload; the outer recipe installs it
    # under the public initrd-provider package name.
    pname = "aos-boot-runtime";
    version = rustcPackage.version;
    # Ordinary fixup must retain the immutable commands embedded by env! before
    # the outer recipe copies this payload into its final installation.
    runtimeDeps = rustcPackage.runtimeDeps;
    inherit build;
    packageLabel = "${prefix}standalone_package";
  };
in
  assert !stdenv.isCross && stdenv.hostPlatform.isLinux;
    rustcPackage.overrideAttrs (previous: {
      src = null;
      buildDeps = [package];
      phases = map (phase:
        if phase.name == "build"
        then {
          name = "build";
          script = ''
            cp ${package}/bin/aos-boot-preparations aos-boot-preparations
          '';
        }
        else phase)
      previous.phases;
      passthru =
        previous.passthru
        // {
          buildDriver = "bazel";
          rustcFallback = rustcPackage;
          bazelBuild = build;
          bazelWorkspace = workspace;
        };
    })
