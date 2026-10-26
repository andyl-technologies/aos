##! Compiles the six installed systemd commands and both packages' release tests.
{
  callPackage,
  mkAosBazelWorkspace,
  mkAosBazelBuild,
  mkAosBazelCheck,
  mkAosBazelToolchains,
  gccUnwrapped,
  aosBazelRepositories,
  aosBazelRustRepositories,
  aosBazelNativeFoundationLibraries,
  sourceInventory ? ../../tools/bazel/metadata/systemd-provider-inventory.json,
}: let
  service = "//crates/activation/aos-activation-systemd:";
  boot = "//crates/boot/aos-boot-runtime:";
  serviceCommands = ["aos-systemd-native-resource-provider" "aos-systemd-credential-encrypt"];
  bootCommands = ["aos-systemd-boot-platform" "aos-systemd-image-stage" "aos-systemd-image-evidence" "aos-systemd-initrd-store"];
  toolchains = mkAosBazelToolchains {gccRuntime = gccUnwrapped;};
  testTools = callPackage ./_aos-systemd-provider-bazel-test-tools.nix {};
  workspaceFor = targets:
    mkAosBazelWorkspace {
      root = ../..;
      inherit sourceInventory toolchains;
      cargoProfile = "release";
      sourceDirectories =
        if sourceInventory == null
        then ["tools/bazel" "third_party/rust" "crates"]
        else [];
      dependencyProfile = "systemd-provider";
      repositories =
        aosBazelRepositories
        // aosBazelRustRepositories.systemd-provider
        // {
          aos_native = aosBazelNativeFoundationLibraries;
          aos_boot_tools = testTools;
        };
      rustcFlags = ["-Copt-level=3" "-Cdebuginfo=0" "-Cdebug-assertions=no" "-Coverflow-checks=no"];
      execRustcFlags = ["-Copt-level=0" "-Cdebuginfo=0" "-Cdebug-assertions=no" "-Coverflow-checks=no"];
      analysisTargets = targets;
    };
  workspace = workspaceFor [
    (service + "production_package")
    (service + "production_license_closure")
    (boot + "systemd_production_package")
    (boot + "systemd_production_license_closure")
  ];
  testWorkspace = workspaceFor (
    map (name: service + "bin_" + name) serviceCommands
    ++ [(service + "license_closure")]
    ++ map (name: boot + name) (["unit" "doc" "license_closure"] ++ map (name: "bin_" + name) (bootCommands ++ ["aos-boot-preparation-provider"]))
  );
in {
  inherit workspace testWorkspace testTools;
  build = mkAosBazelBuild {
    pname = "aos-bazel-systemd-provider-production";
    inherit workspace;
    targets = workspace.selectedTargets;
    retainActionGraph = true;
  };
  tests = mkAosBazelCheck {
    pname = "aos-bazel-systemd-provider-release-tests";
    workspace = testWorkspace;
    targets = testWorkspace.selectedTargets;
    retainActionGraph = true;
  };
  productionInventory = mkAosBazelBuild {
    pname = "aos-bazel-systemd-provider-production-inventory";
    inherit workspace;
    targets = workspace.selectedTargets;
    inventoryOnly = true;
  };
  testInventory = mkAosBazelBuild {
    pname = "aos-bazel-systemd-provider-release-tests-inventory";
    workspace = testWorkspace;
    targets = testWorkspace.selectedTargets;
    inventoryOnly = true;
  };
}
