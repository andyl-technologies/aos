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
  artifactLocatorFor = _selector: {
    artifactReference = {
      _type = "aos-artifact-reference";
      content = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
      store_path = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-control-plane";
      nar_hash = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
      closure = "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
    };
    path = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-control-plane";
  };
  evaluate = bindings:
    lib.evalModules {
      inherit lib;
      modules = [
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
      ];
      packageModules = [
        {
          name = "aos";
          module = aosModule;
        }
        {
          name = "systemd";
          module = {
            imports = [
              ../../pkgs/system/_systemd-abilities/core.nix
              ../../pkgs/system/_systemd-provider.nix
            ];
            config.aos.abilities.instances.manager = {};
          };
        }
      ];
      specialArgs = {
        inherit artifactLocatorFor pkgs;
        provenance = {
          dependencyOwnersOfAttr = _: _: [];
          ownerOfListAttr = _: _: _: "@test";
        };
      };
    };
  initial = evaluate {};
  authoredBindings = builtins.listToAttrs (builtins.map (requestName: let
      request = initial.config.aos.abilities.requests.${requestName};
      implementation = "systemd:${lib.removePrefix "aos:" request.requirement}";
      slot = builtins.head request.scope;
    in {
      name = "test:authored-${builtins.hashString "sha256" requestName}";
      value = {
        request = requestName;
        inherit implementation slot;
        providerInstance = "systemd:manager";
      };
    })
    (builtins.attrNames initial.config.aos.abilities.requests));
  composed = evaluate authoredBindings;
  implementations = composed.config.aos.abilities.implementations;
  interfaces = composed.config.aos.abilities.interfaces;
  implementationInterfaceIdentity = implementation:
    if builtins.isAttrs implementation.interface
    then implementation.interface
    else
      lib.abilities.interfaceIdentity (
        lib.abilities.interfaceDocumentFromDeclaration interfaces.${implementation.interface}
      );
  childImplementationFor = pending: let
    requirement = implementations.${pending.implementation}.requirements.${pending.requirement};
    candidates = builtins.filter (implementationName: let
      implementation = implementations.${implementationName};
      identity = implementationInterfaceIdentity implementation;
    in
      builtins.any
      (selector: lib.abilities.interfaceSelectorMatches selector identity)
      requirement.accepted_interfaces
      && builtins.all (method: builtins.elem method implementation.methods) requirement.methods
      && builtins.all (guarantee: builtins.elem guarantee implementation.guarantees) requirement.guarantees)
    (builtins.attrNames implementations);
  in
    assert builtins.length candidates == 1; builtins.head candidates;
  childBindings = lib.mapAttrs' (requestName: pending: {
      name = "test:child-${builtins.hashString "sha256" requestName}";
      value = {
        request = requestName;
        implementation = childImplementationFor pending;
        inherit (pending) providerInstance slot;
      };
    })
    composed.config.aos.abilities.compositionPendingRequests;
  complete = evaluate (authoredBindings // childBindings);
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
  assert builtins.length (builtins.attrNames abilities.bindings) > 0;
  assert abilities.compositionPendingRequests == {};
  assert builtins.length resources > 0;
  assert builtins.all (unit: builtins.elem unit realizedUnitNames) expectedControlPlaneUnits;
  assert builtins.length complete.config.systemd.providerUnitArtifacts > 0; true
