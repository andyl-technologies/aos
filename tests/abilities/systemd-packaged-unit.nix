##! Fixed-point evaluation of the systemd-owned packaged-unit provider.
{
  lib,
  pkgs,
}: let
  interfaceModule = pkgs.systemd.module.evaluation.module;
  selectedSystemdProvider = import ./_selected-package-provider.nix {
    inherit lib;
    package = pkgs.systemd;
    implementation = "systemd-packaged-unit";
  };
  fileBackedProviderRejected = !(builtins.tryEval (builtins.deepSeq (
      import ./_selected-package-provider.nix {
        inherit lib;
        implementation = "fixture-provider";
        package = {
          pname = "fixture";
          version = "1";
          outputs = ["out"];
          outPath = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-fixture";
          __toString = package: package.outPath;
          module.evaluation.configRoot = ../build/fixtures/ability-module-file.nix;
          contract.value.implementation.providers = [
            {
              name = "fixture-provider";
              provider_module = {
                artifact = {
                  package = "fixture";
                  output = "out";
                };
                path = "provider.nix";
              };
            }
          ];
        };
      }
    ) true)).success;
  artifact = lib.abilities.packageOutput {package = "consumer";};
  consumerModuleFor = unitFile: {config, ...}: let
    declaration = config.aos.abilities.interfaces."systemd:systemd-packaged-unit";
    identity = lib.abilities.interfaceIdentity (
      lib.abilities.interfaceDocumentFromDeclaration declaration
    );
  in {
    config.aos.abilities = {
      requirementTemplates.unit = {
        interface = identity.name;
        inherit (identity) abi descriptor;
        methods = ["apply" "observe"];
        guarantees = [];
        strength = "required";
        fallback = null;
      };
      instances.consumer = {};
      requests.unit = {
        requirement = "unit";
        consumer = "consumer";
        scope = [];
        parameters = {
          source = {
            inherit artifact;
            unit_file = unitFile;
          };
          activation = "enabled";
          prerequisites = [];
          dependencies = {
            after = [];
            before = [];
            requires = [];
            wants = [];
          };
          drop_in = {
            accepted_exit_statuses = [0 2];
            reload_triggers = [];
            search_path = [artifact];
          };
        };
      };
    };
  };

  baseBindings = {
    "test:unit" = {
      request = "consumer:unit";
      implementation = "systemd:systemd-packaged-unit";
      providerInstance = "systemd:manager";
      slot = "example";
    };
  };
  evaluate = consumerModule: bindings:
    lib.evalModules {
      inherit lib;
      modules =
        ([
        lib.abilities.module
        ../../modules/systemd/system.nix
        {
          config.aos.abilities = {
            environment = {
              authority = "test";
              key = "systemd-packaged-unit";
              stage = "host";
            };
            instances."systemd:manager" = {};
            inherit bindings;
          };
        }
      ])
        ++ builtins.map lib.authenticatedModule (([
        {
          name = "systemd";
          inherit (pkgs.systemd) version;
          module = interfaceModule;
        }
        {
          name = "consumer";
          module = consumerModule;
        }
      ]) ++ ([selectedSystemdProvider]));


      specialArgs = {
        inherit pkgs;
        provenance = {
          dependencyOwnersOfAttr = _: _: [];
          ownerOfListAttr = _: _: _: "@test";
        };
      };
    };

  pending = evaluate (consumerModuleFor "lib/systemd/system/example.service") baseBindings;
  effectsChild = builtins.head (builtins.attrValues pending.config.aos.abilities.compositionPendingRequests);
  resolvedBindings =
    baseBindings
    // {
      "test:unit-effects" = {
        request = effectsChild.request;
        implementation = "systemd:systemd-packaged-unit-effects";
        providerInstance = "systemd:manager";
        slot = effectsChild.slot;
      };
    };
  evaluateResolved = consumerModule: evaluate consumerModule resolvedBindings;
  evaluation = evaluateResolved (consumerModuleFor "lib/systemd/system/example.service");
  invalidUnitName = builtins.tryEval (builtins.deepSeq (
      builtins.head (
        builtins.attrValues (
          (evaluateResolved (consumerModuleFor "lib/systemd/system/not-a-unit"))
          .config
          .aos
          .abilities
          .desiredResources
        )
      )
    )
    true);

  abilities = evaluation.config.aos.abilities;
  declaration = abilities.interfaces."systemd:systemd-packaged-unit";
  desired = builtins.head (builtins.attrValues abilities.desiredResources);
  dependencyReference = abilities.compositionOutputs."consumer:unit".unit-resource.value;
  deferredDependency = {
    _type = "aos-request-output-reference";
    request = "consumer:unit";
    output = "unit-resource";
  };
  targetResource =
    desired
    // {
      value =
        desired.value
        // {
          dependencies = desired.value.dependencies // {after = [deferredDependency];};
        };
    };
  prerequisiteResource =
    desired
    // {
      value =
        desired.value
        // {
          prerequisites = [deferredDependency];
        };
    };
  composeFor = resolvedResources: compositionOutputs: resource: let
    provider = import selectedSystemdProvider.module {
      inherit lib pkgs;
      packageName = "systemd";
      outputs = selectedSystemdProvider.outputs;
      config.aos.abilities = {
        inherit resolvedResources compositionOutputs;
        interfaces."systemd:systemd-packaged-unit" = declaration;
      };
    };
    composition = provider.config.aos.abilities.implementations.systemd-packaged-unit.compose {
      resources.test = resource;
    };
  in
    composition.realizations.test;
  validDependency = composeFor abilities.resolvedResources abilities.compositionOutputs targetResource;
  prerequisite = composeFor abilities.resolvedResources abilities.compositionOutputs prerequisiteResource;
  missingReference =
    dependencyReference
    // {
      resource = dependencyReference.resource // {key = "missing";};
    };
  missingResource = builtins.tryEval (builtins.deepSeq (
      composeFor abilities.resolvedResources abilities.compositionOutputs (
        targetResource
        // {
          value =
            targetResource.value
            // {
              dependencies = targetResource.value.dependencies // {after = [missingReference];};
            };
        }
      )
    )
    true);
  duplicateResource = builtins.tryEval (builtins.deepSeq (
      composeFor
      (abilities.resolvedResources // {duplicate = desired;})
      abilities.compositionOutputs
      targetResource
    )
    true);
  missingUnitIdentity = builtins.tryEval (builtins.deepSeq (
      composeFor
      (builtins.mapAttrs (_: resource:
        if resource.resource == dependencyReference.resource
        then resource // {realization.schema = "invalid";}
        else resource)
      abilities.resolvedResources)
      abilities.compositionOutputs
      targetResource
    )
    true);
  mismatchedAuthority = builtins.tryEval (builtins.deepSeq (
      composeFor abilities.resolvedResources abilities.compositionOutputs (
        targetResource
        // {
          value =
            targetResource.value
            // {
              dependencies =
                targetResource.value.dependencies
                // {
                  after = [
                    (dependencyReference
                      // {
                        interface = dependencyReference.interface // {name = "aos.other.resource";};
                      })
                  ];
                };
            };
        }
      )
    )
    true);
  missingReadAuthority = builtins.tryEval (builtins.deepSeq (
      composeFor abilities.resolvedResources abilities.compositionOutputs (
        targetResource
        // {
          value =
            targetResource.value
            // {
              dependencies =
                targetResource.value.dependencies
                // {
                  after = [(dependencyReference // {operations = [];})];
                };
            };
        }
      )
    )
    true);
  directiveFor = realization: sectionName: directiveName: let
    sections = builtins.filter (section: section.name == sectionName) realization.drop_in;
    directives =
      if builtins.length sections != 1
      then []
      else builtins.filter (directive: directive.name == directiveName) (builtins.head sections).directives;
  in
    if builtins.length directives == 1
    then (builtins.head directives).value
    else null;
  after = directiveFor validDependency "Unit" "After";
  prerequisiteAfter = directiveFor prerequisite "Unit" "After";
  successStatus = directiveFor desired.realization "Service" "SuccessExitStatus";
  searchPath = directiveFor desired.realization "Service" "Environment";
  requestSchema = declaration.requestType._abilitySchema;
in
  assert builtins.attrNames pkgs.systemd.abilities
  == [
    "guarantees"
    "implementations"
    "interfaces"
    "requirementTemplates"
  ];
  assert fileBackedProviderRejected;
  assert desired.realization.systemd_unit.unit_name == "example.service";
  assert effectsChild.requirement == "packaged-unit-effects";
  assert abilities.implementations."systemd:systemd-packaged-unit".handlerDescriptor == null;
  assert abilities.implementations."systemd:systemd-packaged-unit-effects".providerModule == null;
  assert desired.realization.source.artifact == artifact;
  assert desired.realization.source.artifact._type == "aos-package-output-selector";
  assert requestSchema.fields.dependencies.fields.after.unique;
  assert requestSchema.fields.dependencies.fields.after.canonical_order;
  assert requestSchema.fields.prerequisites.unique;
  assert requestSchema.fields.prerequisites.canonical_order;
  assert requestSchema.fields.drop_in.fields.accepted_exit_statuses.unique;
  assert requestSchema.fields.drop_in.fields.accepted_exit_statuses.canonical_order;
  assert requestSchema.fields.drop_in.fields.reload_triggers.unique;
  assert requestSchema.fields.drop_in.fields.reload_triggers.canonical_order;
  assert requestSchema.fields.drop_in.fields.search_path.unique;
  assert !(requestSchema.fields.drop_in.fields.search_path.canonical_order or false);
  assert declaration.lifecycle.persistentDeleteMethod == null;
  assert declaration.methods.remove.semantics.requiredTargetAccess == "exclusive-write";
  assert declaration.methods.remove.semantics.stopsProvider;
  assert !(declaration.methods.remove.outputs ? retained-resource);
  assert lib.hasInfix "@@AOS_SYSTEMD_SUBSTITUTION:" after.template;
  assert builtins.attrValues after.substitutions
  == [
    {
      prefix = "";
      suffix = "";
      encoding = "raw";
      source = {
        kind = "systemd-unit-name";
        identity = {
          kind = "unit";
          unit_name = "example.service";
        };
      };
    }
  ];
  assert prerequisiteAfter == null;
  assert !missingResource.success;
  assert !duplicateResource.success;
  assert !missingUnitIdentity.success;
  assert !mismatchedAuthority.success;
  assert !missingReadAuthority.success;
  assert builtins.length evaluation.config.systemd.providerUnitArtifacts == 1;
  assert !(desired.realization ? revision_receipt);
  assert successStatus.template == "0 2";
  assert searchPath.template != "";
  assert !(lib.hasInfix "/nix/store/" searchPath.template);
  assert builtins.length (builtins.attrNames searchPath.substitutions) == 2;
  assert !invalidUnitName.success; true
