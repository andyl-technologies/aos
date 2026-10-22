##! Portable AOS shared libraries qualify together with their Cargo oracle.
{
  pkgs,
  sourceInventory ? ../../tools/bazel/metadata/shared-inventory.json,
}: let
  packages = ["aos-core" "aos-artifact-evidence" "aos-oci-types"];
  label = name: "//crates/shared/${name}";
  integrationTargets = name: let
    directory = ../../crates/shared + "/${name}/tests";
    entries =
      if builtins.pathExists directory
      then builtins.readDir directory
      else {};
  in
    map (file: "${label name}:" + pkgs.lib.removeSuffix ".rs" file)
    (builtins.filter (file: entries.${file} == "regular" && pkgs.lib.hasSuffix ".rs" file) (builtins.attrNames entries));
  workspace = pkgs.mkAosBazelWorkspace {
    root = ../..;
    inherit sourceInventory;
    sourceDirectories = pkgs.lib.optionals (sourceInventory == null) ([
        "tools/bazel/toolchains"
        "tools/bazel/rules"
        "tools/bazel/metadata"
        "tools/bazel/testing"
        "third_party/rust"
      ]
      ++ map (name: "crates/shared/${name}") packages);
    repositories = pkgs.aosBazelRepositories // pkgs.aosBazelRustRepositories.core;
    analysisTargets = map (name: "${label name}:unit") packages;
  };
in rec {
  inherit workspace;

  tests = pkgs.mkAosBazelCheck {
    pname = "aos-bazel-shared-tests";
    inherit workspace;
    targets = pkgs.lib.concatMap (name:
      ["${label name}:license_closure" "${label name}:unit" "${label name}:doc"]
      ++ integrationTargets name)
    packages;
  };
  developer-build = pkgs.mkAosBazelBuild {
    pname = "aos-bazel-shared-developer-tools";
    inherit workspace;
    targets = pkgs.lib.concatMap (name: ["${label name}:clippy" "${label name}:documentation"]) packages;
  };
  developer-tests = pkgs.mkAosBazelCheck {
    pname = "aos-bazel-shared-format";
    inherit workspace;
    targets = map (name: "${label name}:format") packages;
  };
  cargo = import ./_bazel-cargo-oracle.nix {
    inherit pkgs packages;
    pname = "aos-bazel-shared-cargo-oracle";
  };
  oracle = let
    verifier = builtins.path {
      path = ../../tools/bazel/tests;
      name = "aos-shared-parity-tools";
      filter = path: type: type == "regular" && builtins.elem (baseNameOf path) ["verify_protocol.py" "verify_pilot.py"];
    };
    packageOptions = pkgs.lib.concatMap (name: ["--package-path" "${name}=crates/shared/${name}"]) packages;
  in
    pkgs.runCommand "aos-bazel-shared-cargo-parity" {buildDeps = [pkgs.python3];} ''
      mkdir -p "$out"
      ${pkgs.python3}/bin/python3 ${verifier}/verify_protocol.py \
        --tests ${tests}/evidence/tests --inventory ${tests}/inventory.json \
        --messages ${cargo}/cargo-messages.jsonl --cargo-log ${cargo}/cargo-tests.log --output "$out/parity.json" \
        ${pkgs.lib.escapeShellArgs packageOptions}
    '';
  all = pkgs.runCommand "aos-bazel-shared-checks" {buildDeps = [tests oracle developer-build developer-tests];} ''
    mkdir -p "$out"
    cp -r ${tests}/evidence "$out/evidence"
    cp ${tests}/inventory.json "$out/inventory.json"
    cp ${oracle}/parity.json "$out/parity.json"
  '';
}
