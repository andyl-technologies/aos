##! modules/base/checks.nix — Check-to-derivation transformation module
##!
##! Reads check specifications from system.checks and produces runnable VM
##! test derivations in system.build.checks. This keeps check derivation
##! construction inside the module fixed point rather than in external
##! collection scripts.
##!
##! Each check group defined by a module (e.g. system.checks.ssh) becomes a
##! VM test derivation at system.build.checks.ssh.
{
  config,
  pkgs,
  lib,
  ...
}: let
  harness = import ../../lib/testing/vm.nix {inherit pkgs lib;};

  # Proxy object that satisfies mkVMTest's `system` parameter interface.
  # mkVMTest reads: system.config.system.build.{toplevel,kernel}
  #                 system.config.environment.systemPackages
  systemProxy = {
    inherit config;
  };
in {
  options.system.build.checks = lib.mkOption {
    type = lib.types.attrsOf lib.types.package;
    default = {};
    description = ''
      VM test derivations generated from system.checks specifications.
      Each check group becomes a runnable VM test derivation.
    '';
  };

  config.system.build.checks =
    builtins.mapAttrs (
      name: spec:
        harness.mkVMTest {
          inherit name;
          system = systemProxy;
          groupName = name;
          checks = spec.checks;
        }
    )
    config.system.checks;
}
