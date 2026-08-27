# tests/fleet/darling-darwin-c-smoke.nix — Execute a Darwin C binary on Linux.
{
  mkDarlingFleetSpec,
  pkgs,
  systems,
  ...
}: let
  darwinCrossSmoke = import ../build/darwin-cross-smoke.nix {inherit pkgs;};
in
  mkDarlingFleetSpec {
    name = "darling-darwin-c-smoke";
    # The runner needs the fleet agent, not server-test's broad CLI toolbox.
    # mkDarlingFleetSpec bundles the former itself and keeps the image lean.
    system = systems.server;
    artifact = darwinCrossSmoke.passthru.x86.c;
    program = "bin/aos-darwin-c-smoke";
    expectedStdout = "aos Darwin C smoke\n";
  }
