##! Core ability evaluation without an unrelated service domain.
{lib}: let
  coreLib = import ../../lib {system = lib.platform.system;};
  coreEvaluation = coreLib.evalModules {
    lib = coreLib;
    modules = [../../modules/abilities/default.nix];
  };
  serviceEvaluation = lib.evalModules {
    inherit lib;
    modules = [../../modules/abilities/default.nix];
  };
in
  assert coreEvaluation.options.aos ? abilities;
  assert !(coreEvaluation.options.aos ? services);
  assert !(coreLib.abilities.interfaces ? serviceManagement);
  assert serviceEvaluation.options.aos ? abilities;
  assert serviceEvaluation.options.aos ? services;
  assert lib.abilities.interfaces ? serviceManagement; true
