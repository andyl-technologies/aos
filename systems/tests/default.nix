# systems/tests/default.nix — System-level integration test collection
#
# Auto-discovers test definition files in this directory and builds VM test
# derivations for each applicable (system, test) pair. Tests are exposed as
# flake checks under checks.system.{system-name}-{test-name}.
#
# Test types:
#   - "vm"    — Single-VM test using mkVMTest (systemd + agent)
#   - "fleet" — Multi-VM test using mkFleetTest (networked VMs)
#
# Each test file returns a function { lib }: { name, description, type,
# appliesTo, checks/machines/testScript }.
{
  lib,
  pkgs,
  testTools,
  mkSystem,
  systemDefs,
}:
let
  harness = import ../../lib/testing/vm.nix { inherit pkgs lib testTools; };
  fleetHarness = import ../../lib/testing/fleet.nix { inherit pkgs lib testTools; };

  # Discover test definition files
  entries = builtins.readDir ./.;
  testFileNames = builtins.filter (
    name:
    entries.${name} == "regular"
    && builtins.match ".*\\.nix" name != null
    && name != "default.nix"
    && builtins.substring 0 1 name != "_"
  ) (builtins.attrNames entries);

  # Load all test specs
  testSpecs = builtins.map (name: import (./. + "/${name}") { inherit lib; }) testFileNames;

  # Build a single-VM test: evaluate the system with extra check modules,
  # then create a VM test derivation.
  mkSingleVmTest =
    spec: sysName:
    let
      # Create an extra module that injects the test checks
      testModule =
        { config, lib, ... }:
        {
          system.checks."system-${spec.name}" = lib.mkCheckGroup {
            name = "system-${spec.name}";
            description = spec.description;
            checks = spec.checks { inherit config lib; };
          };
        };

      # Evaluate the system with the test module added
      system = mkSystem [
        (systemDefs.${sysName})
        testModule
      ];
    in
    harness.mkVMTest {
      name = "${sysName}-${spec.name}";
      inherit system;
      checks = [ system.config.system.checks."system-${spec.name}" ];
    };

  # Build a fleet (multi-VM) test
  mkFleetVmTest =
    spec:
    let
      # Resolve machine system names to evaluated systems
      machines = builtins.mapAttrs (
        mname: mspec:
        {
          system = mkSystem [ (systemDefs.${mspec.system}) ];
          role = mspec.role or mname;
        }
      ) spec.machines;
    in
    fleetHarness.mkFleetTest {
      name = spec.name;
      inherit machines;
      testScript = spec.testScript;
      timeout = spec.timeout or 300;
    };

  # Collect all single-VM tests
  singleVmTests = builtins.concatMap (
    spec:
    if (spec.type or "vm") == "vm" then
      builtins.map (sysName: {
        name = "${sysName}-${spec.name}";
        value = mkSingleVmTest spec sysName;
      }) (builtins.filter (s: builtins.hasAttr s systemDefs) spec.appliesTo)
    else
      [ ]
  ) testSpecs;

  # Collect all fleet tests
  fleetTests = builtins.concatMap (
    spec:
    if (spec.type or "vm") == "fleet" then
      [
        {
          name = spec.name;
          value = mkFleetVmTest spec;
        }
      ]
    else
      [ ]
  ) testSpecs;
in
builtins.listToAttrs (singleVmTests ++ fleetTests)
