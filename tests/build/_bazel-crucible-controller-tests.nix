##! Compiles the combined controller test graph independently of test execution.
{
  pkgs,
  sourceInventory ? ../../tools/bazel/metadata/crucible-controller-tests-inventory.json,
}: let
  names =
    builtins.filter
    (name: !builtins.elem name ["crucible-qemu-plugin" "crucible-qemu-debug-gateway"])
    (import ../../pkgs/tools/crucible/_packages.nix);
  packages = builtins.listToAttrs (map (name: {
      inherit name;
      value =
        if name == "aos-linux-project-quota"
        then "crates/linux/${name}"
        else "crates/crucible/${name}";
    })
    names);
  controllerVariants = [
    "crucible-engine"
    "crucible-session"
    "crucible-control-api"
    "crucible-control-client"
    "crucible-control-server"
    "crucible-qemu-host"
    "crucible-daemon"
    "crucible-cli"
    "crucible-guest"
    "crucible-test-support"
    "crucible-campaign"
    "crucible-store-s3"
  ];
  # The S3 adapter's development edge enables store test support throughout
  # the combined graph, without enabling the campaign's independent feature.
  excludedTests = ["gate_campaign_mutation_scaling"];
  suffix = name:
    if name == "crucible-store"
    then "_test_support"
    else pkgs.lib.optionalString (builtins.elem name controllerVariants) "_controller";
  testsFor = name: let
    directory = ../.. + "/${packages.${name}}/tests";
    entries =
      if builtins.pathExists directory
      then builtins.readDir directory
      else {};
    integrations =
      map (file: pkgs.lib.removeSuffix ".rs" file)
      (builtins.filter (file:
        entries.${file}
        == "regular"
        && pkgs.lib.hasSuffix ".rs" file
        && !builtins.elem (pkgs.lib.removeSuffix ".rs" file) excludedTests)
      (builtins.attrNames entries));
    unit =
      if name == "crucible-cli"
      then "bin_crucible"
      else "unit";
    binaries =
      pkgs.lib.optional (name == "crucible-store") "bin_crucible-fleet-store"
      ++ pkgs.lib.optional (name == "crucible-guest") "bin_crucible-guest";
  in
    map (target: "//${packages.${name}}:${target}${suffix name}") ([unit] ++ binaries ++ integrations);
  testTargets = pkgs.lib.concatMap testsFor names;
  licenseTargets = map (name:
    "//${packages.${name}}:"
    + (
      if name == "crucible-store"
      then "license_closure_test_support"
      else if builtins.elem name controllerVariants
      then "controller_test_license_closure"
      else "license_closure"
    ))
  names;
  targets = map (target: target + "_binary") testTargets ++ licenseTargets;
  workspace = pkgs.mkAosBazelWorkspace {
    root = ../..;
    inherit sourceInventory;
    sourceDirectories = pkgs.lib.optionals (sourceInventory == null) [
      "BUILD.bazel"
      "AGENTS.md"
      "CONTRIBUTING.md"
      "README.md"
      "default.nix"
      "crates"
      "tools/bazel"
      "third_party/rust"
      "docs"
      "tests/crucible"
      "tests/build/BUILD.bazel"
      "tests/build/_bazel-guest.nix"
      "pkgs/default.nix"
      "pkgs/emulation/qemu.nix"
      "pkgs/emulation/qemu-patches"
    ];
    dependencyProfile = "controller-tests";
    cargoProfile = "release";
    rustcFlags = [
      "-Copt-level=3"
      "-Cdebuginfo=0"
      "-Cdebug-assertions=no"
      "-Coverflow-checks=no"
      "-Cstrip=debuginfo"
      "-Lnative=${pkgs.gccUnwrapped}/lib/gcc/${pkgs.stdenv.hostPlatform.config}/${pkgs.gccUnwrapped.version}"
    ];
    execRustcFlags = ["-Copt-level=0" "-Cdebuginfo=0" "-Cdebug-assertions=no" "-Coverflow-checks=no"];
    repositories =
      pkgs.aosBazelRepositories
      // pkgs.aosBazelRustRepositories.controller-tests
      // {
        aos_native = pkgs.aosBazelStoreLibraries;
        aos_cli_runtime = pkgs.aosBazelCrucibleCliRuntime;
        aos_controller_features = import ./_bazel-crucible-controller-feature-evidence.nix {inherit pkgs;};
      };
    analysisTargets = targets ++ testTargets;
  };
in {
  inherit packages targets testTargets licenseTargets workspace;
  inventory = pkgs.mkAosBazelBuild {
    pname = "aos-bazel-crucible-controller-test-inventory";
    inherit workspace;
    targets = targets ++ testTargets;
    inventoryOnly = true;
  };
  compilation =
    (pkgs.mkAosBazelBuild {
      pname = "aos-bazel-crucible-controller-test-compilation";
      inherit workspace targets;
      retainActionGraph = true;
      sharedBuildCache = false;
    }).overrideAttrs (previous: {
      phases =
        previous.phases
        ++ [
          {
            name = "discover-test-cases";
            script = ''
              cp ${../../tools/bazel/tests/discover_controller_tests.py} discover_controller_tests.py
              cp ${../../tools/bazel/tests/verify_pilot.py} verify_pilot.py
              ${pkgs.python3}/bin/python3 discover_controller_tests.py \
                --events "$out/evidence/events.json" \
                --targets ${builtins.toFile "controller-test-binaries.json" (builtins.toJSON (map (target: target + "_binary") testTargets))} \
                --execution-root "$TMPDIR/bazel/execroot/_main" \
                --output "$out/test-cases.json"
            '';
          }
        ];
    });
  tests = pkgs.mkAosBazelCheck {
    pname = "aos-bazel-crucible-controller-tests";
    inherit workspace;
    targets = testTargets ++ licenseTargets;
    retainActionGraph = true;
    sharedBuildCache = false;
  };
  feature-policy = pkgs.mkAosBazelCheck {
    pname = "aos-bazel-crucible-controller-feature-policy-test";
    inherit workspace;
    targets = ["//crates/crucible/crucible-test-support:feature_powerset_controller"];
    retainActionGraph = true;
    sharedBuildCache = false;
  };
}
