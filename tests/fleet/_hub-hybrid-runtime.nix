# Select immutable runtime packages separately from reviewed fixture sources.
# Fleet Python changes are included in the CLI's default workspace filter, so
# importing packages from the fixture tree would change the compiled identity.
{
  runtimeSource,
  fixtureSource,
  separateDatabase ? true,
  externalDirect ? true,
}: let
  runtime = import runtimeSource {};
  runtimePkgs = runtime.pkgs;
  fixture = import (fixtureSource + "/tests/fleet/hub-hybrid.nix") {
    inherit (runtime) lib mkSystem;
    pkgs = runtimePkgs;
    inherit separateDatabase externalDirect;
  };
  fleetHarness = import (runtimeSource + "/lib/testing/fleet.nix") {
    inherit (runtime) lib;
    pkgs = runtimePkgs;
  };
in {
  inherit fixture;
  test = fleetHarness.mkFleetTest fixture;
  identities = {
    runtimeSource = toString runtimeSource;
    fixtureSource = toString fixtureSource;
    native = toString runtimePkgs.aos-hub;
    client = toString runtimePkgs.aos;
    console = toString runtimePkgs.aos-hub-console-dist;
    worker = toString (
      if externalDirect
      then runtimePkgs.aos-hub-direct-guard-e2e.passthru.workerDist
      else runtimePkgs.aos-hub-worker-dist
    );
    node = toString runtimePkgs.nodejs;
    workerd = toString runtimePkgs.workerd-source;
    driver = toString runtimePkgs.aos-test-driver;
  };
}
