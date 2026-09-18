##! Ensures provider selection only considers modules from selected packages.
{
  lib,
  pkgs,
}: let
  evaluate = packages:
    lib.evalModules {
      inherit lib;
      modules = [
        lib.abilities.module
        {
          config.aos.abilities.environment = {
            authority = "test";
            key = "selected-package-provider-discovery";
            stage = "host";
          };
        }
      ];
      packageModules =
        builtins.map
        lib.abilities.authenticatedPackageModuleRecordFor
        packages;
    };
  select = evaluation:
    import ../../lib/build/select-ability-bindings.nix {
      inherit lib;
      abilities = evaluation.config.aos.abilities;
    };
  selectionFails = evaluation:
    !(builtins.tryEval (builtins.deepSeq (select evaluation) true)).success;

  consumerOnly = evaluate [pkgs.nftables];
  withProvider = evaluate [
    pkgs.nftables
    pkgs.aos-network-ruleset-provider
  ];
  selected = select withProvider;
  selectedBindings = builtins.attrValues selected.bindings;
  selectedInstances = builtins.attrValues selected.instances;
in
  assert selectionFails consumerOnly;
  assert builtins.length selectedBindings == 1;
  assert (builtins.head selectedBindings).request == "nftables:ruleset";
  assert (builtins.head selectedBindings).implementation
  == "aos-network-ruleset-provider:network-ruleset";
  assert builtins.length selectedInstances == 1;
  assert (builtins.head selectedInstances).package == "aos-network-ruleset-provider";
  true
