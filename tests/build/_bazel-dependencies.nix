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
  specifications = specification-packages.core;
  specification-packages = builtins.listToAttrs (map (family: {
    name = family;
    value = pkgs.mkAosBazelPackage {
      pname = "aos-rust-${family}-specifications";
      version = "1";
      build = pkgs.mkAosBazelBuild {
        pname = "aos-bazel-${family}-rust-specifications";
        inherit workspace;
        targets = ["//third_party/rust:${family}_specification_package"];
      };
      packageLabel = "//third_party/rust:${family}_specification_package";
    };
  }) ["core" "device" "store" "guest" "engine" "quota" "session" "control" "qemu-host" "store-s3"]);
  core = pkgs.mkAosBazelCheck {
    pname = "aos-bazel-external-rust-pilot";
    workspace = pkgs.mkAosBazelWorkspace {
      root = ../..;
      sourceDirectories = ["tools/bazel/toolchains" "tools/bazel/rules" "tools/bazel/metadata" "tools/bazel/testing" "third_party/rust" "crates/crucible/engine/crucible-determinism"];
      repositories = pkgs.aosBazelRepositories // pkgs.aosBazelRustRepositories.core;
      analysisTargets = ["//crates/crucible/engine/crucible-determinism:unit"];
    };
    targets = [
      "//crates/crucible/engine/crucible-determinism:unit"
      "//crates/crucible/engine/crucible-determinism:doc"
      "//crates/crucible/engine/crucible-determinism:clippy"
      "//crates/crucible/engine/crucible-determinism:format"
      "//crates/crucible/engine/crucible-determinism:documentation"
    ];
  };
  all = pkgs.runCommand "aos-bazel-external-rust-checks" {buildDeps = [specifications core];} ''
    mkdir -p "$out"
    cp -r ${core}/evidence "$out/evidence"
    cp ${core}/inventory.json "$out/inventory.json"
  '';
}
