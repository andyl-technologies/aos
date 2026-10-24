# Checks the actual standalone Host bank and rejects unowned/online variants.
{
  lib,
  pkgs,
  systems,
}: let
  fixture = import ../fleet/sandbox-host-phase0-readiness.nix {inherit lib pkgs systems;};
  system = fixture.machines.vm.system;
  cfg = system.config;
  accepts = candidate: lib.all (check: check.assertion) candidate.config.assertions;
  withoutOwner = system.extendModules {
    modules = [{aos.sandbox.hostBroker.enable = lib.mkForce false;}];
  };
  withOnlineSubdivision = system.extendModules {
    modules = [
      ({config, ...}: {
        aos.sandbox.resourceBank.policy = {
          hostService = lib.genAttrs config.aos.sandbox.resourceBank._dimensionOrder (_: 1);
          hostControl = lib.genAttrs config.aos.sandbox.resourceBank._dimensionOrder (_: 1);
        };
      })
    ];
  };
in
  assert accepts system;
  assert !accepts withoutOwner;
  assert !accepts withOnlineSubdivision;
  assert !cfg.aos.sandbox.controllerService.enable;
  assert !cfg.aos.sandbox.nixOfflinePrepare.enable;
  assert !cfg.aos.sandbox.hostBroker.componentControl;
  assert !cfg.aos.sandbox.hostBroker.canary;
  assert cfg.environment.etc."aos/resource-bootstrap-v1".source
  == "${cfg.aos.sandbox.resourceBank._imagePolicy}/bootstrap.bin";
    pkgs.runCommand "sandbox-standalone-resource-bank-check" {} ''
      test -s ${cfg.aos.sandbox.resourceBank._imagePolicy}/bootstrap.bin
      touch "$out"
    ''
