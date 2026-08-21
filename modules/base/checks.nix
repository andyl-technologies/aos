##! modules/base/checks.nix — Check-to-derivation transformation module
##!
##! Reads check specifications from system.checks and adds their runnable VM
##! derivations to system.build.checks. Other modules may add build-time
##! artifact checks to the same per-system check namespace.
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
      Per-system validation derivations. VM checks are generated from
      system.checks specifications; image and package modules may add focused
      build-time artifact checks alongside them.
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
