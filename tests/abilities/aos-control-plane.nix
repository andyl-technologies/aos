##! Complete fixed-point regression for the package-owned AOS control plane.
{
  lib,
  pkgs,
}: let
  serviceManagement = lib.abilities.interfaces.serviceManagement;
  serviceTypes = serviceManagement.types;
  command = {
    executable = {
      artifact = lib.abilities.packageOutput {package = "coreutils";};
      entry_point = "bin/true";
      arguments = [];
    };
    ignore_failure = false;
  };
  ownerService = key:
    serviceManagement.forService {
      inherit serviceTypes;
      consumerInstance = "readiness-owners";
      declaration = {
        service = key;
        enabled = true;
        lifecycle = {
          description = "Test owner for ${key}";
          execution_model = "oneshot";
          environment_files = [];
          condition = [];
          pre_start = [];
          start = [command];
          post_start = [];
          stop = [];
          post_stop = [];
          restart = "never";
          restart_delay_millis = 0;
          configuration_change_action = "restart";
          remain_after_exit = true;
          start_timeout_millis = 90000;
          stop_timeout_millis = 90000;
        };
        dependencies = {
          prerequisites = [];
          after = [];
          before = [];
          requires = [];
          wants = [];
        };
        readiness = {
          mechanism = "successful-exit";
          signal_scope = "none";
          timeout_millis = 90000;
        };
      };
    };
  owners = [
    (ownerService "configuration-evaluation")
    (ownerService "package-profile-convergence")
  ];
  ownerContributions = builtins.map serviceManagement.splitContribution owners;
  aosModule = {
    imports = [
      (pkgs.aos.module.evaluation.configRoot + "/control-plane/module.nix")
    ];
    config.aos.abilities = lib.mkMerge (
      [
        {instances.readiness-owners = {};}
      ]
      ++ builtins.map (entry: entry.declarations) ownerContributions
      ++ builtins.map (entry: entry.configured) ownerContributions
    );
  };
  evaluate = bindings:
    lib.evalModules {
      inherit lib;
      modules =
        ([
        lib.abilities.module
        ../../modules/systemd/system.nix
        {
          config = {
            aos.abilities = {
              environment = {
                authority = "test";
                key = "aos-control-plane";
                stage = "host";
              };
              inherit bindings;
            };
            aos.config.unitGraph.enable = true;
          };
        }
      ])
        ++ builtins.map lib.authenticatedModule (([
        {
          name = "aos";
          module = aosModule;
        }
        {
          name = "systemd";
          module = {
            imports = [
              ../../pkgs/system/_systemd-abilities/module.nix
              ../../pkgs/system/_systemd-abilities/share/aos/providers/systemd.nix
            ];
            config.aos.abilities.instances.manager = {};
          };
        }
      ]));

      specialArgs = {
        inherit pkgs;
        provenance = {
          dependencyOwnersOfAttr = _: _: [];
          ownerOfListAttr = _: _: _: "@test";
        };
      };
    };
  initial = evaluate {};
  complete = import ../../lib/build/selected-ability-bindings.nix {inherit lib;} {
    inherit evaluate;
  };
  abilities = complete.config.aos.abilities;
  resources = builtins.attrValues abilities.desiredResources;
  realizedUnitName = resource: let
    identity = resource.realization.systemd_unit or null;
  in
    if identity == null
    then null
    else identity.unit_name or identity.template_unit_name;
  realizedUnitNames = builtins.filter (name: name != null) (builtins.map realizedUnitName resources);
  expectedControlPlaneUnits = [
    "aos-activate.service"
    "aos-config-render.target"
    "aos-config.target"
    "aos-fetch.target"
    "aos-graph-compile.service"
    "aos-pkg-fetch@.service"
    "aos-pkg-install@.service"
    "aos-preset.service"
  ];
in
  assert builtins.length (builtins.attrNames initial.config.aos.abilities.requests) > 0;
  assert builtins.length (builtins.attrNames abilities.bindings) > 0;
  assert abilities.compositionPendingRequests == {};
  assert builtins.length resources > 0;
  assert builtins.all (unit: builtins.elem unit realizedUnitNames) expectedControlPlaneUnits;
  assert builtins.length complete.config.systemd.providerUnitArtifacts > 0; true
