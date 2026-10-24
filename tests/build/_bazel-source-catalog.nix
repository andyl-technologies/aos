##! Compares Bazel-owned source coverage with the temporary Cargo oracle.
{pkgs}: let
  workspace = pkgs.mkAosBazelWorkspace {
    root = ../..;
    sourceDirectories = [
      "BUILD.bazel"
      "crates"
      "crates/accache/accache"
      "tools/bazel/rules"
      "tools/bazel/metadata"
      "tools/bazel/toolchains"
    ];
    analysisTargets = ["//:source_catalog_package" "//crates:source_catalog_package"];
  };
  build = pkgs.mkAosBazelBuild {
    pname = "aos-bazel-source-catalog";
    inherit workspace;
    targets = workspace.selectedTargets;
    sharedBuildCache = false;
  };
  package = label: pname:
    pkgs.mkAosBazelPackage {
      inherit pname build;
      version = "1";
      packageLabel = label;
    };
in rec {
  inherit workspace build;
  repository = package "//:source_catalog_package" "aos-source-catalog";
  crates = package "//crates:source_catalog_package" "aos-workspace-source-catalog";
  all = pkgs.runCommand "aos-bazel-source-catalog-checks" {buildDeps = [pkgs.python3];} ''
    mkdir -p "$out"
    PYTHONDONTWRITEBYTECODE=1 ${pkgs.python3}/bin/python3 \
      ${../../tools/bazel/tests/verify_source_catalog.py} \
      --root ${workspace.source} \
      --oracle ${../../tools/bazel/metadata/cargo-inventory.json} \
      --repository ${repository}/share/aos/source-catalog.json \
      --crates ${crates}/share/aos/source-catalog.json \
      --execution ${build}/evidence/execution.json \
      --output "$out/report.json"
    cp ${repository}/share/aos/source-catalog.json "$out/repository.json"
    cp ${crates}/share/aos/source-catalog.json "$out/crates.json"
  '';
}
