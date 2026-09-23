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
    imports = [../../pkgs/tools/aos/_abilities/control-plane/module.nix];
    config.aos.abilities = lib.mkMerge (
      [
        {instances.readiness-owners = {};}
      ]
      ++ builtins.map (entry: entry.declarations) ownerContributions
      ++ builtins.map (entry: entry.configured) ownerContributions
    );
  };
  selectedSystemdProvider = import ./_selected-package-provider.nix {
    inherit lib;
    package = pkgs.systemd;
    implementation = "service-lifecycle";
  };
  evaluate = selection:
    lib.evalModules {
      inherit lib;
      modules = [
        ../../modules/abilities/default.nix
        {
          config = {
            aos.abilities = {
              environment = {
                authority = "test";
                key = "aos-control-plane";
                stage = "host";
              };
              instances = {"systemd:manager" = {};} // selection.instances;
              inherit (selection) bindings;
            };
            aos.config.unitGraph.enable = true;
          };
        }
      ];
      packageModules = [
        {
          name = "aos";
          module = aosModule;
        }
        (lib.abilities.authenticatedPackageModuleRecordFor pkgs.systemd)
      ];
      selectedProviderModules = [selectedSystemdProvider];
      specialArgs = {
        inherit pkgs;
        abilityResolution = {
          inherit (selection) requests requirements;
        };
        provenance = {
          dependencyOwnersOfAttr = _: _: [];
          ownerOfListAttr = _: _: _: "@test";
        };
      };
    };
  emptySelection = {
    instances = {};
    bindings = {};
    requests = {};
    requirements = {};
  };
  select = lib.abilities.selectBindings;
  mergeSelection = current: additions: {
    instances = current.instances // additions.instances;
    bindings = current.bindings // additions.bindings;
    requests = current.requests // additions.requests;
    requirements = current.requirements // additions.requirements;
  };
  initial = evaluate emptySelection;
  authoredSelection = select initial.config.aos.abilities;
  composedSelection = mergeSelection emptySelection authoredSelection;
  composed = evaluate composedSelection;
  completeSelection = mergeSelection composedSelection (select composed.config.aos.abilities);
  complete = evaluate completeSelection;
  initrd = lib.evalModules {
    inherit lib;
    modules = [
      ../../modules/abilities/default.nix
      {
        config = {
          aos.abilities.environment = {
            authority = "test";
            key = "aos-control-plane-initrd";
            stage = "initrd";
          };
          aos.config.unitGraph.enable = true;
        };
      }
    ];
    packageModules = [
      {
        name = "aos";
        module = ../../pkgs/tools/aos/_abilities/control-plane/module.nix;
      }
    ];
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
    "aos-config.target"
    "aos-graph-compile.service"
  ];
in
  assert builtins.length (builtins.attrNames initial.config.aos.abilities.requests) > 0;
  assert initrd.config.aos.abilities.requests == {};
  assert builtins.length (builtins.attrNames abilities.bindings) > 0;
  assert abilities.compositionPendingRequests == {};
  assert builtins.length resources > 0;
  assert builtins.all (unit: builtins.elem unit realizedUnitNames) expectedControlPlaneUnits;
  assert builtins.length complete.config.systemd.providerUnitPlans > 0; true
