##! CLI conversion checkpoints; runtime qualification is kept explicit.
{system ? builtins.currentSystem}: let
  pkgs = (import ../../.. {inherit system;}).pkgs;
  architectureOracleSource = import ../../../pkgs/tools/aos/_workspace-source.nix {inherit (pkgs) lib;};
  verifier = builtins.path {
    path = ./.;
    name = "aos-cli-parity-tools";
    filter = path: type:
      type == "regular" && builtins.elem (baseNameOf path) ["verify_cli.py" "verify_protocol.py" "verify_pilot.py"];
  };
  testConfiguration = fleet: let
    candidate = import ../../../tests/build/_bazel-aos-cli.nix {inherit pkgs fleet;};
    cargo = import ../../../tests/build/_bazel-aos-cli-cargo.nix {inherit pkgs fleet;};
    editor = import ../../../tests/build/_bazel-aos-cli-editor.nix {inherit pkgs fleet;};
    profile =
      if fleet
      then "fleet"
      else "default";
    parity = pkgs.runCommand "aos-bazel-aos-cli-${profile}-cargo-parity" {buildDeps = [pkgs.python3];} ''
      mkdir -p "$out"
      ${pkgs.python3}/bin/python3 ${verifier}/verify_cli.py \
        --tests ${candidate.tests}/evidence/tests \
        --inventory ${candidate.tests}/inventory.json \
        --cargo ${cargo} --output "$out/parity.json"
    '';
    execution-profiles = import ../qualification/rust-profiles.nix {
      inherit pkgs cargo parity;
      pname = "aos-bazel-aos-cli-${profile}-test-profiles";
      build = candidate.tests;
    };
  in
    candidate
    // editor
    // {
      inherit cargo execution-profiles;
      test-parity = parity;
      oracle = pkgs.runCommand "aos-bazel-aos-cli-${profile}-qualified-test-profiles" {buildDeps = [parity execution-profiles];} ''
        mkdir -p "$out"
        cp ${parity}/parity.json "$out/parity.json"
        cp ${execution-profiles}/evidence.json "$out/execution-profiles.json"
      '';
    };
in {
  architecture = pkgs.runCommand "aos-bazel-architecture-cargo-parity" {buildDeps = [pkgs.python3];} ''
    mkdir -p "$out"
    ${pkgs.python3}/bin/python3 ${./verify_architecture.py} \
      --architecture ${pkgs.aosBazelArchitecture}/architecture.json \
      --workspace-directory ${architectureOracleSource}/crates --output "$out/parity.json"
  '';
  default = testConfiguration false;
  fleet = testConfiguration true;
  production = import ../../../tests/build/_bazel-aos-cli-production.nix {inherit pkgs;};
  production-precise = import ../../../tests/build/_bazel-aos-cli-production.nix {
    inherit pkgs;
    sourceInventory = ../../../tools/bazel/metadata/aos-cli-inventory.json;
  };
  execution-profiles = import ../../../tests/build/_bazel-aos-cli-execution-profiles.nix {inherit pkgs;};
}
