##! Compiles boot identity with Bazel and preserves its production install phases.
{
  rustcPackage,
  mkAosBazelWorkspace,
  mkAosBazelToolchains,
  mkAosBazelCheck,
  mkAosBazelPackage,
  gccUnwrapped,
  stdenv,
}: let
  targets = [
    "//crates/boot/aos-boot-identity:package"
    "//crates/boot/aos-boot-identity:unit"
    "//crates/boot/aos-boot-identity:uki_cli"
    "//crates/boot/aos-boot-identity:doc"
  ];
  workspace = mkAosBazelWorkspace {
    root = ../..;
    sourceInventory = ../../tools/bazel/metadata/boot-pilot-inventory.json;
    # The ordinary GCC search resolves -lgcc_s through its static redirect.
    # Do not put the separate shared-runtime output ahead of that search path.
    toolchains = mkAosBazelToolchains {gccRuntime = gccUnwrapped;};
    # The production recipe uses rustc's development defaults, without Cargo's
    # workspace test-profile overrides. Declare the same target/tool settings.
    rustcFlags = ["-Copt-level=0" "-Cdebuginfo=0" "-Cdebug-assertions=yes" "-Coverflow-checks=yes"];
    execRustcFlags = ["-Copt-level=0" "-Cdebuginfo=0" "-Cdebug-assertions=yes" "-Coverflow-checks=yes"];
    analysisTargets = targets;
  };
  build = mkAosBazelCheck {
    pname = "aos-bazel-boot-identity-production";
    inherit workspace targets;
    retainActionGraph = true;
  };
  package = mkAosBazelPackage {
    pname = "aos-boot-identity";
    version = rustcPackage.version;
    inherit build;
    packageLabel = "//crates/boot/aos-boot-identity:package";
  };
in
  assert !stdenv.isCross;
    rustcPackage.overrideAttrs (previous: {
      src = null;
      buildDeps = [package];
      phases = map (phase:
        if phase.name == "build"
        then {
          name = "build";
          script = ''
            cp ${package}/bin/aos-boot-identity aos-boot-identity
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
