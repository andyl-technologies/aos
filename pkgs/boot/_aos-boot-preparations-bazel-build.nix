##! Compiles standalone initrd orchestration from its configured source inventory.
{
  mkAosBazelWorkspace,
  mkAosBazelToolchains,
  mkAosBazelCheck,
  aosBazelRepositories,
  aosBazelBootTools,
  gccUnwrapped,
  sourceInventory ? ../../tools/bazel/metadata/initrd-preparation-inventory.json,
}: let
  prefix = "//crates/boot/aos-boot-runtime:";
  targets = map (name: prefix + name) ["standalone_package" "standalone_unit" "standalone_production_license_closure"];
  workspace = mkAosBazelWorkspace {
    root = ../..;
    inherit sourceInventory;
    sourceDirectories =
      if sourceInventory == null
      then ["tools/bazel/toolchains" "tools/bazel/rules" "tools/bazel/metadata" "tools/bazel/testing" "third_party/rust" "crates/boot/aos-boot-runtime"]
      else [];
    repositories = aosBazelRepositories // {aos_boot_tools = aosBazelBootTools;};
    toolchains = mkAosBazelToolchains {gccRuntime = gccUnwrapped;};
    # Match the direct-rustc production recipe's development defaults.
    rustcFlags = ["-Copt-level=0" "-Cdebuginfo=0" "-Cdebug-assertions=yes" "-Coverflow-checks=yes"];
    execRustcFlags = ["-Copt-level=0" "-Cdebuginfo=0" "-Cdebug-assertions=yes" "-Coverflow-checks=yes"];
    analysisTargets = targets;
  };
in
  mkAosBazelCheck {
    pname = "aos-bazel-initrd-preparation-production";
    inherit workspace targets;
    retainActionGraph = true;
  }
