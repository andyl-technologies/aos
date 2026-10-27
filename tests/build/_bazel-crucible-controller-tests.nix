##! Compiles the combined controller test graph independently of test execution.
{
  pkgs,
  sourceInventory ? ../../tools/bazel/metadata/crucible-controller-tests-inventory.json,
  toolchains ? pkgs.aosBazelToolchains,
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
  nativeConstraints = [
    "@platforms//cpu:${
      if pkgs.stdenv.hostPlatform.isx86_64
      then "x86_64"
      else "aarch64"
    }"
    "@platforms//os:linux"
  ];
  targets = map (target: target + "_binary") testTargets ++ licenseTargets;
  clippyTargets = map (name:
    if name == "aos-linux-project-quota"
    then "//${packages.${name}}:clippy"
    else "//${packages.${name}}:clippy_all")
  names;
  # All-target lint analysis includes the guest's static production copies.
  # Keep the controller's shared SQLite provider and expose the guest runtime
  # as a separate provider; host targets do not acquire static link flags.
  nativeLibraries =
    pkgs.runCommand "aos-bazel-controller-native-libraries" {
      sharedBuildCache = false;
    } ''
      mkdir -p "$out"
      for entry in ${pkgs.aosBazelStoreLibraries}/*; do
        name="''${entry##*/}"
        case "$name" in
          BUILD.bazel|nix-support) ;;
          *) ln -s "$entry" "$out/$name" ;;
        esac
      done
      cp ${pkgs.aosBazelStoreLibraries}/BUILD.bazel "$out/BUILD.bazel"
      chmod u+w "$out/BUILD.bazel"
      ln -s ${pkgs.aosBazelGuestLibraries}/static "$out/static"
      cat >> "$out/BUILD.bazel" <<'BUILD'

      cc_library(
          name = "static_runtime",
          additional_linker_inputs = ["static/closure.json"] + glob(["static/lib/*.a"]),
          linkopts = ["-L${pkgs.aosBazelGuestLibraries}/static/lib", "-static", "-no-pie"],
          tags = ["aos-license:apache-host"],
          target_compatible_with = ${builtins.toJSON nativeConstraints},
      )
      BUILD
    '';
  workspaceFor = developmentLint:
    pkgs.mkAosBazelWorkspace {
      root = ../..;
      inherit sourceInventory toolchains;
      sourceDirectories = pkgs.lib.optionals (sourceInventory == null) [
        "BUILD.bazel"
        "AGENTS.md"
        "CONTRIBUTING.md"
        "README.md"
        "LICENSES"
        "default.nix"
        "crates"
        "tools/bazel"
        "third_party/rust"
        "docs"
        "tests/crucible"
        "tests/build/BUILD.bazel"
        "tests/build/_bazel-guest.nix"
        "docs/rfcs/0014-signal-driven-fault-model"
        "docs/users/crucible"
        "modules/base/build.nix"
        "modules/profiles/ability-crucible.nix"
        "pkgs/kernel/linux-crucible.nix"
        "pkgs/kernel/linux.nix"
        "pkgs/tools/aos-ability-crucible.nix"
        "pkgs/tools/crucible-fixtures.nix"
        "pkgs/tools/crucible-fleet-store.nix"
        "pkgs/tools/crucible-guest.nix"
        "pkgs/tools/crucible/_cargo-source.nix"
        "pkgs/tools/crucible/_packages.nix"
        "pkgs/tools/crucible/_release-manifest.nix"
        "pkgs/tools/crucible/_source.nix"
        "pkgs/tools/crucible/crucible.nix"
        "stdenv/phases.nix"
        "tests/build/_bazel-crucible-controller-tests.nix"
        "tools/bazel/launcher.py"
        "pkgs/default.nix"
        "pkgs/emulation/qemu.nix"
        "pkgs/emulation/qemu-patches"
        "pkgs/emulation/crucible-qemu-plugin.nix"
        "pkgs/emulation/_crucible-qemu-bazel-installed.nix"
        "pkgs/tools/crucible/_debug-gateway.nix"
      ];
      dependencyProfile = "controller-tests";
      cargoProfile =
        if developmentLint
        then "debug"
        else "release";
      # Cargo Clippy uses the development profile. Debug-only integration
      # helpers must remain visible without enabling extra crate features.
      rustcFlags =
        (
          if developmentLint
          then ["-Copt-level=0" "-Cdebuginfo=2" "-Cdebug-assertions=yes" "-Coverflow-checks=yes" "-Cstrip=none"]
          else ["-Copt-level=3" "-Cdebuginfo=0" "-Cdebug-assertions=no" "-Coverflow-checks=no" "-Cstrip=debuginfo"]
        )
        ++ ["-Lnative=${pkgs.gccUnwrapped}/lib/gcc/${pkgs.stdenv.hostPlatform.config}/${pkgs.gccUnwrapped.version}"];
      execRustcFlags =
        if developmentLint
        then ["-Copt-level=0" "-Cdebuginfo=0" "-Cdebug-assertions=yes" "-Coverflow-checks=yes"]
        else ["-Copt-level=0" "-Cdebuginfo=0" "-Cdebug-assertions=no" "-Coverflow-checks=no"];
      repositories =
        pkgs.aosBazelRepositories
        // pkgs.aosBazelRustRepositories.controller-tests
        // {
          aos_native = nativeLibraries;
          aos_cli_runtime = pkgs.aosBazelCrucibleCliRuntime;
          aos_controller_features = import ./_bazel-crucible-controller-feature-evidence.nix {inherit pkgs;};
          aos_architecture = import ./_bazel-crucible-controller-audit-inputs.nix {inherit pkgs;};
        };
      analysisTargets = targets ++ testTargets ++ clippyTargets;
    };
  workspace = workspaceFor false;
  lintWorkspace = workspaceFor true;
in {
  inherit packages targets testTargets licenseTargets clippyTargets workspace lintWorkspace;
  inventory =
    (pkgs.mkAosBazelBuild {
      pname = "aos-bazel-crucible-controller-test-inventory";
      inherit workspace;
      targets = targets ++ testTargets ++ clippyTargets;
      inventoryOnly = true;
    }).overrideAttrs (_: {
      # Repeating the complete test and lint selection exceeds execve's
      # per-argument limit when the generated phase script is passed inline.
      passBuildScriptAsFile = true;
    });
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
  lint = pkgs.mkAosBazelBuild {
    pname = "aos-bazel-crucible-controller-clippy";
    workspace = lintWorkspace;
    targets = clippyTargets;
    retainActionGraph = true;
    sharedBuildCache = false;
  };
  harness-lint = pkgs.mkAosBazelCheck {
    pname = "aos-bazel-crucible-controller-harness-lint";
    inherit workspace;
    targets = ["//crates/crucible/crucible-test-support:harness_lint_controller"];
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
  architecture = pkgs.mkAosBazelCheck {
    pname = "aos-bazel-crucible-controller-architecture-tests";
    inherit workspace;
    targets = [
      "//crates/crucible/crucible-test-support:control_plane_boundary_controller"
      "//crates/crucible/crucible-test-support:crate_layer_graph_controller"
      "//crates/crucible/crucible-test-support:crate_artifact_types_controller"
    ];
    retainActionGraph = true;
    sharedBuildCache = false;
  };
  license-boundary = pkgs.mkAosBazelCheck {
    pname = "aos-bazel-crucible-controller-license-boundary";
    inherit workspace;
    targets = ["//crates/crucible/crucible-test-support:gate_license_boundary_controller"];
    retainActionGraph = true;
    sharedBuildCache = false;
  };
  dependencies = pkgs.mkAosBazelCheck {
    pname = "aos-bazel-crucible-controller-dependencies";
    inherit workspace;
    targets = map (name: "//crates/crucible/crucible-test-support:${name}_controller") [
      "harness_components"
      "standalone_dependencies"
      "single_scheduler_boundary"
    ];
    retainActionGraph = true;
    sharedBuildCache = false;
  };
  gate-targets = pkgs.mkAosBazelCheck {
    pname = "aos-bazel-crucible-controller-gate-targets";
    inherit workspace;
    targets = ["//crates/crucible/crucible-test-support:gate_target_mapping_controller"];
    retainActionGraph = true;
    sharedBuildCache = false;
  };
  campaign-traceability = pkgs.mkAosBazelCheck {
    pname = "aos-bazel-crucible-controller-campaign-traceability";
    inherit workspace;
    targets = ["//crates/crucible/crucible-test-support:campaign_gate_traceability_controller"];
    retainActionGraph = true;
    sharedBuildCache = false;
  };
}
