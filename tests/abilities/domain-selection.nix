##! Checks that native domains are selected by modules rather than global catalogs.
{lib}: let
  core = lib.evalModules {
    inherit lib;
    modules = [../../modules/abilities/default.nix];
  };
  service = lib.evalModules {
    inherit lib;
    modules = [../../modules/abilities/default.nix ../../pkgs/system/_service-management/module.nix];
  };
in
  assert !(core.options.aos ? services);
  assert core.config.aos.abilities == {};
  assert service.options.aos ? services;
  assert service.config.aos.abilities.serviceManagement.operations.realize.handler == null;
  assert service.config.aos.activation.graph.order == []; true
