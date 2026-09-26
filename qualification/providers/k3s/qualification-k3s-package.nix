##! Composes package verification with the staged K3s image and OCI fleet.
{
  pkgs,
  lib,
}: {
  name,
  identity,
  packageExecutable,
  systemVariant,
  topology,
}: let
  fleetName = "${name}-fleet";
  fleet = import ../../../lib/testing/qualification-image.nix {inherit pkgs lib;} {
    name = fleetName;
    inherit identity;
    scenarioSource = ./qualification_k3s_fleet.py;
    scenarioModules = {
      qualification_image = ../../../lib/testing/qualification-image.py;
      qualification_k3s_bindings = ./qualification_k3s_bindings.py;
      qualification_k3s_oci = ./qualification_k3s_oci.py;
      k3s_lifecycle = ./k3s-lifecycle.py;
    };
  };
in
  assert builtins.substring 0 11 packageExecutable == "/nix/store/";
  assert systemVariant != "";
  assert builtins.elem topology ["combined-worker" "control-plane-worker"];
    pkgs.buildPackages.writeShellScriptBin name ''
      set -euo pipefail

      export AOS_QUALIFICATION_BOUND_IMAGE_VARIANT=${lib.escapeShellArg systemVariant}
      export AOS_QUALIFICATION_SUBJECT_BINDER=${lib.escapeShellArg (builtins.toString ./qualification_k3s_bindings.py)}
      export AOS_QUALIFICATION_SUBJECT_BINDER_ARGUMENTS=${lib.escapeShellArg (builtins.toJSON {inherit topology;})}

      # The first adapter verifies NARs and emits its validated package report.
      # Fleet execution extends that report after actual staged guest behavior.
      ${packageExecutable} > package-response.json

      export AOS_QUALIFICATION_BOUND_K3S_TOPOLOGY=${lib.escapeShellArg topology}
      exec ${fleet}/bin/${fleetName}
    ''
