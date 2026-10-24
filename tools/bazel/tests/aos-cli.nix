##! CLI conversion checkpoints; runtime qualification is kept explicit.
{system ? builtins.currentSystem}: let
  pkgs = (import ../../.. {inherit system;}).pkgs;
  verifier = builtins.path {
    path = ./.;
    name = "aos-cli-parity-tools";
    filter = path: type:
      type == "regular" && builtins.elem (baseNameOf path) ["verify_cli.py" "verify_protocol.py" "verify_pilot.py"];
  };
  testConfiguration = fleet: let
    candidate = import ../../../tests/build/_bazel-aos-cli.nix {inherit pkgs fleet;};
    cargo = import ../../../tests/build/_bazel-aos-cli-cargo.nix {inherit pkgs fleet;};
    profile =
      if fleet
      then "fleet"
      else "default";
  in
    candidate
    // {
      inherit cargo;
      oracle = pkgs.runCommand "aos-bazel-aos-cli-${profile}-cargo-parity" {buildDeps = [pkgs.python3];} ''
        mkdir -p "$out"
        ${pkgs.python3}/bin/python3 ${verifier}/verify_cli.py \
          --tests ${candidate.tests}/evidence/tests \
          --inventory ${candidate.tests}/inventory.json \
          --cargo ${cargo} --output "$out/parity.json"
      '';
    };
in {
  default = testConfiguration false;
  fleet = testConfiguration true;
  production = import ../../../tests/build/_bazel-aos-cli-production.nix {inherit pkgs;};
}
