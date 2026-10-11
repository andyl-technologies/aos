# Export the normal agent-driven fleet inputs without executing its test
# derivation. The host controller permits independent review of owner-private
# observations; it does not use the interactive harness or change VM networking.
{
  source,
  runtimeSourceIdentity ? null,
  separateDatabase ? true,
  readRevisionFixture ? null,
}: let
  aos = import source {};
  spec = import (source + "/tests/fleet/hub-hybrid.nix") {
    inherit (aos) lib pkgs;
    mkSystem = import ./_hub-fixture-system.nix {inherit (aos) mkSystem;};
    inherit runtimeSourceIdentity separateDatabase readRevisionFixture;
    externalDirect = true;
    runtimeSource = source;
  };
  # Retain the exact authored test phase while constructing the ordinary
  # derivation. Its manifest and Python inputs include the image/helper closure.
  observedPackages =
    aos.pkgs
    // {
      mkDerivation = arguments:
        (aos.pkgs.mkDerivation arguments)
        // {controllerPhases = arguments.phases or [];};
    };
  harness = import (source + "/lib/testing/fleet.nix") {
    inherit (aos) lib;
    pkgs = observedPackages;
  };
  fleet = harness.mkFleetTest spec;
  selectedPhases = builtins.filter (phase: phase.name == "test") fleet.controllerPhases;
in
  assert builtins.length selectedPhases == 1; {
    version = 1;
    source = builtins.toString source;
    inherit separateDatabase;
    name = spec.name;
    timeout = spec.timeout;
    machines = builtins.attrNames spec.machines;
    testDerivation = fleet.drvPath;
    driverExecutable = "${aos.pkgs.aos-test-driver}/bin/aos-test-driver";
    nixExecutable = "${aos.pkgs.nix}/bin/nix";
    runtimePath = aos.lib.concatStringsSep ":" [
      "${aos.pkgs.coreutils}/bin"
      "${aos.pkgs.qemu}/bin"
      "${aos.pkgs.socat}/bin"
      # gptfdisk installs its disk tools in sbin.
      "${aos.pkgs.gptfdisk}/sbin"
      "${aos.pkgs.python3}/bin"
      "${aos.pkgs.bash}/bin"
    ];
    controllerPhase = (builtins.head selectedPhases).script;
    scope = "normal fleet input export only; no build, launch or qualification";
  }
