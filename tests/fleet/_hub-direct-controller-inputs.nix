# Export the normal agent-driven fleet inputs without executing its test
# derivation. The host controller permits independent review of owner-private
# observations; it does not use the interactive harness or change VM networking.
{
  source,
  separateDatabase ? true,
}: let
  aos = import source {};
  spec = import (source + "/tests/fleet/hub-hybrid.nix") {
    inherit (aos) lib mkSystem pkgs;
    inherit separateDatabase;
    externalDirect = true;
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
    runtimePath = aos.lib.concatStringsSep ":" (builtins.map (package: "${package}/bin") [
      aos.pkgs.coreutils
      aos.pkgs.qemu
      aos.pkgs.socat
      aos.pkgs.gptfdisk
      aos.pkgs.python3
      aos.pkgs.bash
    ]);
    controllerPhase = (builtins.head selectedPhases).script;
    scope = "normal fleet input export only; no build, launch or qualification";
  }
