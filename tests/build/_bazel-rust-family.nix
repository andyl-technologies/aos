##! Qualifies one connected Rust family without changing its production builders.
{
  pkgs,
  pname,
  packages,
  sourceInventory ? null,
  extraSourceDirectories ? [],
  dependencyProfile ? null,
}: let
  names = builtins.attrNames packages;
  label = name: "//${packages.${name}}";
  directoryTargets = name: directoryName: let
    directory = ../.. + "/${packages.${name}}/${directoryName}";
    entries =
      if builtins.pathExists directory
      then builtins.readDir directory
      else {};
  in
    map (file: "${label name}:" + pkgs.lib.removeSuffix ".rs" file)
    (builtins.filter (file: entries.${file} == "regular" && pkgs.lib.hasSuffix ".rs" file) (builtins.attrNames entries));
  workspace = pkgs.mkAosBazelWorkspace {
    root = ../..;
    inherit sourceInventory dependencyProfile;
    sourceDirectories = pkgs.lib.optionals (sourceInventory == null) ([
        "tools/bazel/toolchains"
        "tools/bazel/rules"
        "tools/bazel/metadata"
        "tools/bazel/testing"
        "third_party/rust"
      ]
      ++ builtins.attrValues packages ++ extraSourceDirectories);
    repositories = pkgs.aosBazelRepositories // pkgs.aosBazelRustRepositories.core // pkgs.aosBazelRustRepositories.device;
    analysisTargets = map (name: "${label name}:unit") names;
  };
in rec {
  inherit workspace;
  tests = pkgs.mkAosBazelCheck {
    pname = "${pname}-tests";
    inherit workspace;
    targets = pkgs.lib.concatMap (name:
      ["${label name}:license_closure" "${label name}:unit" "${label name}:doc"]
      ++ directoryTargets name "tests" ++ directoryTargets name "examples")
    names;
  };
  developer-build = pkgs.mkAosBazelBuild {
    pname = "${pname}-developer-tools";
    inherit workspace;
    targets = pkgs.lib.concatMap (name: ["${label name}:clippy" "${label name}:documentation"]) names;
  };
  developer-tests = pkgs.mkAosBazelCheck {
    pname = "${pname}-format";
    inherit workspace;
    targets = map (name: "${label name}:format") names;
  };
  cargo = import ./_bazel-cargo-oracle.nix {
    inherit pkgs;
    pname = "${pname}-cargo-oracle";
    packages = names;
  };
  oracle = let
    verifier = builtins.path {
      path = ../../tools/bazel/tests;
      name = "aos-rust-family-parity-tools";
      filter = path: type: type == "directory" || builtins.elem (baseNameOf path) ["verify_protocol.py" "verify_pilot.py"];
    };
    packageOptions = pkgs.lib.concatMap (name: ["--package-path" "${name}=${packages.${name}}"]) names;
  in
    pkgs.runCommand "${pname}-cargo-parity" {buildDeps = [pkgs.python3];} ''
      mkdir -p "$out"
      ${pkgs.python3}/bin/python3 ${verifier}/verify_protocol.py \
        --tests ${tests}/evidence/tests --inventory ${tests}/inventory.json \
        --messages ${cargo}/cargo-messages.jsonl --cargo-log ${cargo}/cargo-tests.log --output "$out/parity.json" \
        ${pkgs.lib.escapeShellArgs packageOptions}
    '';
  all = pkgs.runCommand "${pname}-checks" {buildDeps = [tests oracle developer-build developer-tests];} ''
    mkdir -p "$out"
    cp -r ${tests}/evidence "$out/evidence"
    cp ${tests}/inventory.json "$out/inventory.json"
    cp ${oracle}/parity.json "$out/parity.json"
  '';
}
