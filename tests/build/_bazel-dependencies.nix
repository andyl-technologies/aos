##! Dependency resolution is an explicit update; ordinary targets export specs.
{pkgs}: let
  workspace = pkgs.mkAosBazelWorkspace {
    root = ../..;
    sourceDirectories = ["tools/bazel/toolchains" "tools/bazel/rules" "tools/bazel/metadata" "third_party/rust"];
    analysisTargets = ["//third_party/rust:core_specification_package"];
  };
in rec {
  build = pkgs.mkAosBazelBuild {
    pname = "aos-bazel-rust-specifications";
    inherit workspace;
    targets = ["//third_party/rust:core_specification_package"];
  };
  specifications = pkgs.mkAosBazelPackage {
    pname = "aos-rust-core-specifications";
    version = "1";
    inherit build;
    packageLabel = "//third_party/rust:core_specification_package";
  };
  core = pkgs.mkAosBazelCheck {
    pname = "aos-bazel-external-rust-pilot";
    workspace = pkgs.mkAosBazelWorkspace {
      root = ../..;
      sourceDirectories = ["tools/bazel/toolchains" "tools/bazel/rules" "tools/bazel/metadata" "tools/bazel/testing" "third_party/rust" "crates/crucible/engine/crucible-determinism"];
      repositories = pkgs.aosBazelRepositories // pkgs.aosBazelRustRepositories.core;
      analysisTargets = ["//crates/crucible/engine/crucible-determinism:unit"];
    };
    targets = ["//crates/crucible/engine/crucible-determinism:unit" "//crates/crucible/engine/crucible-determinism:doc"];
  };
  all = pkgs.runCommand "aos-bazel-external-rust-checks" {buildDeps = [specifications core];} ''
    mkdir -p "$out"
    cp -r ${core}/evidence "$out/evidence"
    cp ${core}/inventory.json "$out/inventory.json"
  '';
}
