##! Builds the browser library and bindings with source-built Linux execution tools.
{
  pkgs,
  sourceInventory ? ../../tools/bazel/metadata/hub-console-wasm-inventory.json,
}: let
  native = import ./_bazel-hub-console.nix {
    inherit pkgs;
    sourceInventory = null;
  };
  sourceDirectories =
    ["tools/bazel" "third_party/rust" "api/proto"]
    ++ builtins.attrValues native.packages ++ builtins.attrValues native.dependencyPackages;
  targets = [
    "//crates/hub/aos-hub-console:lib"
    "//crates/hub/aos-hub-console:aos-hub-console"
    "//crates/hub/aos-hub-console:browser_dist"
    "//crates/hub/aos-hub-console:production_license_closure"
    "//crates/hub/aos-hub-api:generated_sources_evidence"
  ];
  workspace = pkgs.mkAosBazelWorkspace {
    root = ../..;
    inherit sourceInventory;
    sourceDirectories = pkgs.lib.optionals (sourceInventory == null) sourceDirectories;
    repositories =
      pkgs.aosBazelRepositories
      // pkgs.aosBazelRustRepositories.hub-console-wasm
      // {
        aos_codegen = pkgs.aosBazelCodegenTools;
        aos_wasm_tools = pkgs.aosBazelWasmTools;
      };
    dependencyProfile = "hub-console-wasm";
    targetPlatform = "//tools/bazel/toolchains:wasm32";
    compileOnly = true;
    rustcFlags = ["-Copt-level=s" "-Cdebuginfo=0" "-Clto=thin" "-Cembed-bitcode=yes" "-Ccodegen-units=1" "-Cstrip=symbols" "-Cdebug-assertions=no" "-Coverflow-checks=no"];
    analysisTargets = targets;
  };
in rec {
  inherit workspace;
  build = pkgs.mkAosBazelBuild {
    pname = "aos-bazel-hub-console-browser";
    inherit workspace targets;
    retainActionGraph = true;
  };
  developer-build = pkgs.mkAosBazelBuild {
    pname = "aos-bazel-hub-console-browser-developer";
    inherit workspace;
    targets = ["//crates/hub/aos-hub-console:browser_clippy"];
  };
  test-compilation = pkgs.mkAosBazelBuild {
    pname = "aos-bazel-hub-console-browser-test-compilation";
    inherit workspace;
    targets = ["//crates/hub/aos-hub-console:browser_test_artifacts"];
    retainActionGraph = true;
  };
  all =
    pkgs.runCommand "aos-bazel-hub-console-browser-checks" {
      buildDeps = [build developer-build test-compilation];
    } ''
      mkdir -p "$out"
      ln -s ${build} "$out/production"
      ln -s ${developer-build} "$out/developer"
      ln -s ${test-compilation} "$out/test-compilation"
    '';
  inventory = pkgs.mkAosBazelBuild {
    pname = "aos-bazel-hub-console-browser-inventory";
    inherit workspace;
    targets =
      targets
      ++ ["//crates/hub/aos-hub-console:browser_clippy" "//crates/hub/aos-hub-console:browser_test_artifacts"]
      ++ map (path: "//${path}:source_package") (builtins.attrValues native.dependencyPackages);
    inventoryOnly = true;
  };
}
