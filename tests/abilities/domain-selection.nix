##! Core ability evaluation without an unrelated service domain.
{lib}: let
  coreLib = import ../../lib {system = lib.platform.system;};
  coreEvaluation = coreLib.evalModules {
    lib = coreLib;
    modules = [../../modules/abilities/default.nix];
  };
  serviceOnlyLib = import ../../lib {
    system = lib.platform.system;
    abilityInterfaceDirectory = ./fixtures/service-management-only;
  };
  serviceOnlyEvaluation = serviceOnlyLib.evalModules {
    lib = serviceOnlyLib;
    modules = [
      ../../modules/abilities/default.nix
      {aos.services.example.enable = false;}
    ];
  };
  serviceEvaluation = lib.evalModules {
    inherit lib;
    modules = [../../modules/abilities/default.nix];
  };
in
  assert coreEvaluation.options.aos ? abilities;
  assert !(coreEvaluation.options.aos ? services);
  assert !(coreLib.abilities.interfaces ? serviceManagement);
  assert serviceOnlyLib.abilities.interfaces ? serviceManagement;
  assert !(serviceOnlyLib.abilities.interfaces ? servicePolicy);
  assert serviceOnlyEvaluation.config.aos.services.example.service == "example";
  assert !(serviceOnlyEvaluation.config.aos.services.example ? policy);
  assert serviceEvaluation.options.aos ? abilities;
  assert serviceEvaluation.options.aos ? services;
  assert lib.abilities.interfaces ? serviceManagement; true
