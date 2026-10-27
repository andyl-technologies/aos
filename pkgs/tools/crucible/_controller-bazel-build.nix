##! Keeps the three installed controller executables in separate feature graphs.
{
  lib,
  stdenv,
  gccUnwrapped,
  mkAosBazelWorkspace,
  mkAosBazelBuild,
  aosBazelRepositories,
  aosBazelRustRepositories,
  aosBazelStoreLibraries,
  aosBazelCrucibleCliRuntime,
  sourceInventories ? {},
}: let
  contexts = {
    cli = {
      package = "crucible-cli";
      profile = "crucible-cli";
      licenseTarget = "production_license_closure";
    };
    debugger = {
      package = "crucible-engine";
      profile = "engine";
      licenseTarget = "controller_license_closure";
    };
    scenario = {
      package = "crucible-daemon";
      profile = "daemon";
      licenseTarget = "controller_license_closure";
    };
  };
  buildContext = name: context: let
    prefix = "//crates/crucible/${context.package}:";
    targets = ["${prefix}controller_artifact" "${prefix}${context.licenseTarget}"];
    sourceInventory = sourceInventories.${name} or null;
    workspace = mkAosBazelWorkspace {
      root = ../../..;
      inherit sourceInventory;
      sourceDirectories = lib.optionals (sourceInventory == null) [
        "BUILD.bazel"
        "crates"
        "tools/bazel"
        "third_party/rust"
        "docs/rfcs/0020-crucible-campaigns"
        "tests/crucible"
      ];
      dependencyProfile = context.profile;
      cargoProfile = "release";
      rustcFlags = [
        "-Copt-level=3"
        "-Cdebuginfo=0"
        "-Cdebug-assertions=no"
        "-Coverflow-checks=no"
        "-Cstrip=debuginfo"
        "-Lnative=${gccUnwrapped}/lib/gcc/${stdenv.hostPlatform.config}/${gccUnwrapped.version}"
      ];
      execRustcFlags = ["-Copt-level=0" "-Cdebuginfo=0" "-Cdebug-assertions=no" "-Coverflow-checks=no"];
      repositories =
        aosBazelRepositories
        // aosBazelRustRepositories.${context.profile}
        // {
          aos_native = aosBazelStoreLibraries;
          aos_cli_runtime = aosBazelCrucibleCliRuntime;
        };
      analysisTargets = targets;
    };
  in {
    inherit workspace targets;
    build = mkAosBazelBuild {
      pname = "aos-bazel-crucible-controller-${name}";
      inherit workspace targets;
      retainActionGraph = true;
    };
    inventory = mkAosBazelBuild {
      pname = "aos-bazel-crucible-controller-${name}-inventory";
      inherit workspace targets;
      inventoryOnly = true;
    };
  };
in
  builtins.mapAttrs buildContext contexts
