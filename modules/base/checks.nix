##! modules/base/checks.nix — Check-to-derivation transformation module
##!
##! Reads check specifications from system.checks and cloud-init test specs
##! from system.cloudInitTests, and produces runnable VM test derivations
##! in system.build.checks. This keeps check derivation construction inside
##! the module fixed point rather than in external collection scripts.
##!
##! Each check group defined by a module (e.g. system.checks.ssh) becomes a
##! VM test derivation at system.build.checks.ssh. Cloud-init tests become
##! derivations prefixed with their spec name.
{
  config,
  pkgs,
  lib,
  ...
}:
let
  # Import the VM test harness. All test tools are AOS packages.
  testTools = {
    qemu = pkgs.qemu;
    socat = pkgs.socat;
    jq = pkgs.jq;
  };
  harness = import ../../lib/testing/vm.nix { inherit pkgs lib testTools; };

  # Proxy object that satisfies mkVMTest's `system` parameter interface.
  # mkVMTest reads: system.config.system.build.{toplevel,kernel}
  #                 system.config.environment.systemPackages
  systemProxy = {
    inherit config;
  };
in
{
  options.system.build.checks = lib.mkOption {
    type = lib.types.attrsOf lib.types.package;
    default = { };
    description = ''
      VM test derivations generated from system.checks and
      system.cloudInitTests specifications. Each check group becomes
      a runnable VM test derivation.
    '';
  };

  config.system.build.checks =
    # Module-defined VM checks (system.checks.*)
    builtins.mapAttrs (
      name: checkGroup:
      harness.mkVMTest {
        inherit name;
        system = systemProxy;
        checks = [ checkGroup ];
      }
    ) config.system.checks
    # Cloud-init tests (system.cloudInitTests.*)
    // builtins.mapAttrs (
      name: spec:
      harness.mkVMTest {
        inherit name;
        system = systemProxy;
        checks = [ spec.checks ];
        userdata = spec.userdata;
      }
    ) config.system.cloudInitTests;
}
