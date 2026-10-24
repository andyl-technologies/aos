##! Builds the actual registry SPA entry point and its immutable browser assets.
{
  pkgs,
  sourceInventory ? ../../tools/bazel/metadata/registry-web-wasm-inventory.json,
}: let
  native = import ./_bazel-registry-web.nix {inherit pkgs;};
  prefix = "//crates/registry/aos-registry-web:";
  targets = map (name: prefix + name) ["lib" "shared" "aos-registry-spa" "browser_dist" "production_license_closure"];
  workspace = pkgs.mkAosBazelWorkspace {
    root = ../..;
    inherit sourceInventory;
    sourceDirectories = pkgs.lib.optionals (sourceInventory == null) (
      ["tools/bazel/toolchains" "tools/bazel/rules" "tools/bazel/metadata" "tools/bazel/testing" "third_party/rust"]
      ++ builtins.attrValues native.packages ++ builtins.attrValues native.dependencyPackages
    );
    repositories =
      pkgs.aosBazelRepositories
      // pkgs.aosBazelRustRepositories.registry-web-wasm
      // {aos_wasm_tools = pkgs.aosBazelWasmTools;};
    dependencyProfile = "registry-web-wasm";
    targetPlatform = "//tools/bazel/toolchains:wasm32";
    compileOnly = true;
    rustcFlags = ["-Copt-level=3" "-Cdebuginfo=0" "-Cdebug-assertions=no" "-Coverflow-checks=no"];
    analysisTargets = targets;
  };
in rec {
  inherit workspace;
  build = pkgs.mkAosBazelBuild {
    pname = "aos-bazel-registry-web-browser";
    inherit workspace targets;
    retainActionGraph = true;
  };
  installed = pkgs.mkAosBazelPackage {
    pname = "aos-registry-web";
    version = "0.1.0";
    inherit build;
    packageLabel = "${prefix}browser_dist";
  };
  developer-build = pkgs.mkAosBazelBuild {
    pname = "aos-bazel-registry-web-browser-developer";
    inherit workspace;
    targets = ["${prefix}browser_clippy"];
  };
  test-compilation = pkgs.mkAosBazelBuild {
    pname = "aos-bazel-registry-web-browser-test-compilation";
    inherit workspace;
    targets = ["${prefix}browser_test_artifacts"];
    retainActionGraph = true;
  };
  cargo = import ./_bazel-registry-web-wasm-cargo.nix {inherit pkgs;};
  feature-parity = let
    verifier = builtins.path {
      path = ../../tools/bazel/tests;
      name = "aos-registry-web-browser-feature-parity-tools";
      filter = path: type: type == "regular" && builtins.elem (baseNameOf path) ["verify_protocol.py" "verify_pilot.py"];
    };
    packageOptions =
      pkgs.lib.concatMap (name: ["--package-path" "${name}=${native.packages.${name}}"])
      (builtins.attrNames native.packages)
      ++ pkgs.lib.concatMap (name: ["--dependency-package-path" "${name}=${native.dependencyPackages.${name}}"])
      (builtins.attrNames native.dependencyPackages);
  in
    pkgs.runCommand "aos-bazel-registry-web-browser-features" {buildDeps = [pkgs.python3];} ''
      mkdir -p "$out"
      ${pkgs.python3}/bin/python3 ${verifier}/verify_protocol.py --features-only \
        --inventory ${build}/inventory.json --messages ${cargo}/cargo-messages.jsonl \
        --output "$out/parity.json" ${pkgs.lib.escapeShellArgs packageOptions}
    '';
  package-parity = let
    verifier = builtins.path {
      path = ../../tools/bazel/tests;
      name = "aos-registry-web-browser-package-parity-tools";
      filter = path: type: type == "regular" && builtins.elem (baseNameOf path) ["verify_registry_browser.py" "verify_worker.py" "verify_protocol.py" "verify_pilot.py"];
    };
  in
    pkgs.runCommand "aos-bazel-registry-web-browser-package-parity" {buildDeps = [pkgs.python3 pkgs.nodejs];} ''
      mkdir -p "$out"
      ${pkgs.python3}/bin/python3 ${verifier}/verify_registry_browser.py \
        --bazel ${installed} --cargo ${cargo} \
        --stylesheet ${../../crates/registry/aos-registry-web/assets/app.css} \
        --node ${pkgs.nodejs}/bin/node --output "$out/parity.json"
    '';
  page-staging = pkgs.runCommand "aos-bazel-registry-web-browser-page-staging" {buildDeps = [pkgs.python3 pkgs.apr];} ''
    mkdir -p "$out"
    ${pkgs.python3}/bin/python3 ${../../tools/bazel/tests/verify_registry_staging.py} \
      --apr ${pkgs.apr}/bin/apr --package ${installed} --output "$out/parity.json"
  '';
  inventory = pkgs.mkAosBazelBuild {
    pname = "aos-bazel-registry-web-browser-inventory";
    inherit workspace;
    inventoryOnly = true;
    targets =
      targets
      ++ ["${prefix}browser_clippy" "${prefix}browser_test_artifacts"]
      ++ map (path: "//${path}:source_package") (builtins.attrValues native.dependencyPackages);
  };
  all =
    pkgs.runCommand "aos-bazel-registry-web-browser-checks" {
      buildDeps = [build installed developer-build test-compilation feature-parity package-parity page-staging];
    } ''
      mkdir -p "$out"
      ln -s ${build} "$out/production"
      ln -s ${installed} "$out/package"
      ln -s ${developer-build} "$out/developer"
      ln -s ${test-compilation} "$out/test-compilation"
      ln -s ${feature-parity} "$out/features"
      ln -s ${package-parity} "$out/package-parity"
      ln -s ${page-staging} "$out/page-staging"
    '';
}
