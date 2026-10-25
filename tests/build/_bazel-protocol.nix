##! Shared protocol libraries compile and test through the offline Bazel graph.
{
  pkgs,
  sourceInventory ? ../../tools/bazel/metadata/protocol-inventory.json,
}: let
  protocol = "//crates/crucible/crucible-qemu-protocol";
  shmem = "//crates/crucible/crucible-qemu-shmem";
  integrationTargets = name: let
    entries = builtins.readDir (../../crates/crucible + "/${name}/tests");
  in
    map (file: "//crates/crucible/${name}:" + pkgs.lib.removeSuffix ".rs" file)
    (builtins.filter (file: entries.${file} == "regular" && pkgs.lib.hasSuffix ".rs" file) (builtins.attrNames entries));
  workspace = pkgs.mkAosBazelWorkspace {
    root = ../..;
    inherit sourceInventory;
    sourceDirectories = pkgs.lib.optionals (sourceInventory == null) [
      "tools/bazel/toolchains"
      "tools/bazel/rules"
      "tools/bazel/metadata"
      "tools/bazel/testing"
      "third_party/rust"
      "crates/crucible/crucible-qemu-protocol"
      "crates/crucible/crucible-qemu-shmem"
      "docs/rfcs/0020-crucible-campaigns"
    ];
    repositories = pkgs.aosBazelRepositories // pkgs.aosBazelRustRepositories.core;
    # Match the native Cargo test profile while keeping procedural macros and
    # build scripts in its independent, unoptimized execution profile.
    rustcFlags = ["-Copt-level=s" "-Cdebuginfo=0" "-Cdebug-assertions=yes" "-Coverflow-checks=yes"];
    execRustcFlags = ["-Copt-level=0" "-Cdebuginfo=0" "-Cdebug-assertions=yes" "-Coverflow-checks=yes"];
    analysisTargets = ["${protocol}:unit" "${shmem}:unit"];
  };
in rec {
  inherit workspace;

  tests = pkgs.mkAosBazelCheck {
    pname = "aos-bazel-protocol-tests";
    inherit workspace;
    retainActionGraph = true;
    targets =
      ["${protocol}:license_closure" "${shmem}:license_closure" "${protocol}:unit" "${protocol}:doc" "${shmem}:unit" "${shmem}:doc" "${shmem}:crucible-shmem-abi-header"]
      ++ integrationTargets "crucible-qemu-protocol"
      ++ integrationTargets "crucible-qemu-shmem";
  };
  developer-build = pkgs.mkAosBazelBuild {
    pname = "aos-bazel-protocol-developer-tools";
    inherit workspace;
    targets = ["${protocol}:clippy" "${shmem}:clippy" "${protocol}:documentation" "${shmem}:documentation"];
  };
  developer-tests = pkgs.mkAosBazelCheck {
    pname = "aos-bazel-protocol-format";
    inherit workspace;
    targets = ["${protocol}:format" "${shmem}:format"];
  };
  cargo = import ./_bazel-cargo-oracle.nix {
    inherit pkgs;
    pname = "aos-bazel-protocol-cargo-oracle";
    packages = ["crucible-qemu-protocol" "crucible-qemu-shmem"];
    captureCompilerArguments = true;
  };
  oracle = let
    verifier = builtins.path {
      path = ../../tools/bazel/tests;
      name = "aos-protocol-parity-tools";
      filter = path: type: type == "regular" && builtins.elem (baseNameOf path) ["verify_protocol.py" "verify_pilot.py"];
    };
  in
    pkgs.runCommand "aos-bazel-protocol-cargo-parity" {buildDeps = [pkgs.python3];} ''
      mkdir -p "$out"
      ${pkgs.python3}/bin/python3 ${verifier}/verify_protocol.py \
        --tests ${tests}/evidence/tests --inventory ${tests}/inventory.json \
        --messages ${cargo}/cargo-messages.jsonl --cargo-log ${cargo}/cargo-tests.log --output "$out/parity.json"
    '';
  execution-profiles = import ./_bazel-protocol-execution-profiles.nix {inherit pkgs tests cargo;};
  all = pkgs.runCommand "aos-bazel-protocol-checks" {buildDeps = [tests oracle developer-build developer-tests execution-profiles];} ''
    mkdir -p "$out"
    cp -r ${tests}/evidence "$out/evidence"
    cp ${tests}/inventory.json "$out/inventory.json"
    cp ${oracle}/parity.json "$out/parity.json"
    cp ${execution-profiles}/evidence.json "$out/execution-profiles.json"
  '';
}
