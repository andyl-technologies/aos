# Reuse the independently runnable enrollment check's exact variable-store seed.
{
  lib,
  pkgs,
  systems,
}: let
  fleetHarness = import ../../lib/testing/fleet.nix {inherit lib pkgs;};
  enrollmentSpec = import ./secure-boot-enrollment.nix {inherit pkgs systems;};
in
  fleetHarness.mkFleetTest enrollmentSpec
