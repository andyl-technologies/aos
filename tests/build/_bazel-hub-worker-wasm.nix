##! Compiles and packages the Worker with explicit source-built execution tools.
{
  pkgs,
  featureSet ? "default",
  sourceInventory ? ../../tools/bazel/metadata/hub-worker-wasm-inventory.json,
}: let
  profiles = {
    default = "hub-worker-wasm";
    do-e2e = "hub-worker-wasm-do-e2e";
    all-features = "hub-worker-wasm-all-features";
  };
  profile = profiles.${featureSet} or (throw "unknown Worker Wasm feature set: ${featureSet}");
  packages = {
    aos-hub-worker = "crates/hub/aos-hub-worker";
  };
  dependencyPackages = {
    aos-artifact-evidence = "crates/shared/aos-artifact-evidence";
    aos-core = "crates/shared/aos-core";
    aos-hub-api = "crates/hub/aos-hub-api";
    aos-hub-db = "crates/hub/aos-hub-db";
    aos-hub-model = "crates/hub/aos-hub-model";
    aos-hub-service = "crates/hub/aos-hub-service";
    aos-hub-ui = "crates/hub/aos-hub-ui";
    aos-module-docs = "crates/aos/modules/aos-module-docs";
    aos-module-format = "crates/aos/modules/aos-module-format";
    aos-oci-types = "crates/shared/aos-oci-types";
    aos-registry-format = "crates/aos/registry/aos-registry-format";
    aos-release-format = "crates/aos/release/aos-release-format";
  };
  targets = [
    "//crates/hub/aos-hub-worker:lib"
    "//crates/hub/aos-hub-worker:shared"
    "//crates/hub/aos-hub-worker:worker_dist"
    "//crates/hub/aos-hub-worker:production_license_closure"
    "//crates/hub/aos-hub-api:generated_sources_evidence"
    "//crates/hub/aos-hub-service:generated_assets_evidence"
  ];
  workspace = pkgs.mkAosBazelWorkspace {
    root = ../..;
    inherit sourceInventory;
    sourceDirectories =
      pkgs.lib.optionals (sourceInventory == null)
      (["tools/bazel" "third_party/rust" "api/proto"] ++ builtins.attrValues packages ++ builtins.attrValues dependencyPackages);
    repositories =
      pkgs.aosBazelRepositories
      // pkgs.aosBazelRustRepositories.${profile}
      // {
        aos_codegen = pkgs.aosBazelCodegenTools;
        aos_console_assets = pkgs.aosBazelConsoleAssets;
        aos_worker_tools = pkgs.aosBazelWorkerTools;
      };
    dependencyProfile = profile;
    targetPlatform = "//tools/bazel/toolchains:wasm32";
    compileOnly = true;
    # Preserve the production cold-instantiation profile and JS entropy backend.
    rustcFlags = [
      "-Copt-level=s"
      "-Cdebuginfo=0"
      "-Clto=fat"
      "-Cembed-bitcode=yes"
      "-Ccodegen-units=1"
      "-Cpanic=abort"
      "-Cstrip=symbols"
      "-Cdebug-assertions=no"
      "-Coverflow-checks=no"
      ''--cfg=getrandom_backend="wasm_js"''
    ];
    analysisTargets = targets;
  };
in rec {
  inherit workspace packages dependencyPackages;
  installed = pkgs.mkAosBazelPackage {
    pname = "aos-hub-worker";
    version = "0.1.0";
    inherit build;
    packageLabel = "//crates/hub/aos-hub-worker:worker_dist";
  };
  cargo = let
    original = pkgs.callPackage ../../pkgs/tools/aos-hub-worker-dist.nix {
      cargoFeatures =
        {
          default = "";
          do-e2e = "do-e2e";
          all-features = "do-e2e query-timing";
        }.${
          featureSet
        };
      # Compare packaging against the same declared browser artifacts.
      buildPackages = pkgs.buildPackages // {aos-hub-console-dist = pkgs.aosBazelConsoleAssets;};
    };
    command = ''-j"$NIX_BUILD_CORES"'';
    capture = ''-j"$NIX_BUILD_CORES" --message-format=json > "$out/cargo-messages.jsonl"'';
  in
    original.overrideAttrs (old: {
      pname = "aos-bazel-${profile}-cargo";
      sharedBuildCache = false;
      phases =
        map (
          phase:
            if phase.name != "build-wasm"
            then phase
            else
              assert builtins.length (pkgs.lib.splitString command phase.script) == 2;
              assert !(pkgs.lib.hasInfix "/dev/shm" phase.script);
                phase
                // {
                  script =
                    ''                      mkdir -p "$out"
                    ''
                    + builtins.replaceStrings [command] [capture] phase.script;
                }
        )
        old.phases;
    });
  parity = pkgs.runCommand "aos-bazel-${profile}-cargo-parity" {buildDeps = [pkgs.python3 pkgs.nodejs];} ''
    mkdir -p "$out"
    cp ${../../tools/bazel/tests/verify_worker.py} verify_worker.py
    cp ${../../tools/bazel/tests/verify_protocol.py} verify_protocol.py
    cp ${../../tools/bazel/tests/verify_pilot.py} verify_pilot.py
    cat > packages.json <<'JSON'
    ${builtins.toJSON (packages // dependencyPackages)}
    JSON
    ${pkgs.python3}/bin/python3 verify_worker.py \
      --bazel ${installed} --cargo ${cargo} --build ${build} \
      --node ${pkgs.nodejs}/bin/node --packages packages.json \
      ${pkgs.lib.optionalString (featureSet != "default") "--test-hooks"} \
      --output "$out/parity.json"
  '';
  all = pkgs.runCommand "aos-bazel-${profile}-qualified-checks" {buildDeps = [parity developer-build];} ''
    mkdir -p "$out"
    cp ${parity}/parity.json "$out/parity.json"
    ln -s ${build} "$out/production"
    ln -s ${installed} "$out/deployment"
    ln -s ${developer-build} "$out/developer"
  '';
  live-launcher = assert featureSet == "do-e2e";
    pkgs.callPackage ../../pkgs/tools/aos-hub-worker-do-e2e.nix {workerDist = installed;};
  live-runtime = assert featureSet == "do-e2e"; let
    testing = import ../../lib/testing {
      inherit pkgs;
      inherit (pkgs) lib;
    };
  in
    testing.mkVMTest {
      name = "aos-bazel-hub-worker-do-e2e-live";
      rootfsDeps = [live-launcher];
      memory = 2048;
      testScript = ''
        ${pkgs.nix}/bin/nix-store --load-db < /usr/lib/aos/nix-registration
        export NIX_REMOTE=""
        ${live-launcher}/bin/aos-hub-worker-do-e2e
      '';
    };
  build = pkgs.mkAosBazelBuild {
    pname = "aos-bazel-${profile}";
    inherit workspace targets;
    retainActionGraph = true;
  };
  developer-build = pkgs.mkAosBazelBuild {
    pname = "aos-bazel-${profile}-developer";
    inherit workspace;
    targets = ["//crates/hub/aos-hub-worker:worker_clippy"];
  };
  inventory = pkgs.mkAosBazelBuild {
    pname = "aos-bazel-${profile}-inventory";
    inherit workspace;
    targets =
      targets
      ++ ["//crates/hub/aos-hub-worker:worker_clippy"]
      ++ map (path: "//${path}:source_package") (builtins.attrValues packages ++ builtins.attrValues dependencyPackages);
    inventoryOnly = true;
  };
}
