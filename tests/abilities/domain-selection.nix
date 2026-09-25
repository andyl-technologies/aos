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
      {
        aos.abilities.environment = {
          authority = "test";
          key = "service-only";
          stage = "host";
        };
        aos.services.example = {
          enable = true;
          lifecycle = {
            description = "Service-only domain fixture";
            execution_model = "foreground";
            environment_files = [];
            condition = [];
            pre_start = [];
            start = [
              {
                executable = {
                  artifact = serviceOnlyLib.abilities.packageOutput {package = "fixture";};
                  entry_point = "bin/example";
                  arguments = [];
                };
                ignore_failure = false;
              }
            ];
            post_start = [];
            stop = [];
            post_stop = [];
            restart = "never";
            restart_delay_millis = 0;
            remain_after_exit = false;
            start_timeout_millis = 1000;
            stop_timeout_millis = 1000;
          };
        };
      }
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
  assert builtins.attrNames serviceOnlyEvaluation.config.aos.abilities.requests != [];
  assert serviceEvaluation.options.aos ? abilities;
  assert serviceEvaluation.options.aos ? services;
  assert lib.abilities.interfaces ? serviceManagement; true
