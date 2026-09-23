##! Fixed-point evaluation of the systemd-owned packaged-unit provider.
{
  lib,
  pkgs,
}: let
  packageModule = lib.abilities.authenticatedPackageModuleRecordFor pkgs.systemd;
  selectedSystemdProvider = import ./_selected-package-provider.nix {
    inherit lib;
    package = pkgs.systemd;
    implementation = "systemd-packaged-unit";
    dependencies.${
      builtins.toJSON {
        output = artifact.output;
        package = artifact.package;
      }
    } = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-example";
  };
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
  evaluate = consumerModule: bindings: abilityResolution:
    lib.evalModules {
      inherit lib;
      modules = [
        ../../modules/abilities/default.nix
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
      ];
      packageModules = [
        packageModule
        {
          name = "consumer";
          module = consumerModule;
        }
      ];
      selectedProviderModules = [selectedSystemdProvider];
      specialArgs = {
        inherit pkgs abilityResolution;
        provenance = {
          dependencyOwnersOfAttr = _: _: [];
          ownerOfListAttr = _: _: _: "@test";
        };
      };
    };

  emptyResolution = {
    requests = {};
    requirements = {};
  };
  pending = evaluate (consumerModuleFor "lib/systemd/system/example.service") baseBindings emptyResolution;
  effectsChild = builtins.head (builtins.attrValues pending.config.aos.abilities.compositionPendingRequests);
  resolvedAbilityInputs = {
    requests.${effectsChild.request} = effectsChild.declaration;
    requirements.${effectsChild.declaration.requirement} =
      pending.config.aos.abilities.compositionRequirements.${effectsChild.declaration.requirement};
  };
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
  evaluateResolved = consumerModule: evaluate consumerModule resolvedBindings resolvedAbilityInputs;
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
  dependencyReference = abilities.compositionOutputs."consumer:unit".resource.value;
  deferredDependency = {
    _type = "aos-request-output-reference";
    request = "consumer:unit";
    output = "resource";
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
      packageArtifactForRequest = request: selector:
        if request == "consumer:unit" && selector == artifact
        then
          selectedSystemdProvider.outputs.dependencies.${
            builtins.toJSON {
              output = artifact.output;
              package = artifact.package;
            }
          }
        else throw "packaged-unit fixture requested an undeclared consumer artifact";
      options = {};
      config.aos = {
        abilities = {
          inherit resolvedResources compositionOutputs;
          inherit (abilities) interfaces;
        };
        inherit (evaluation.config.aos) systemd;
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
  assert desired.realization.systemd_unit.unit_name == "example.service";
  assert effectsChild.requirement == "packaged-unit-effects";
  assert abilities.implementations."systemd:systemd-packaged-unit".handlerDescriptor == null;
  assert abilities.implementations."systemd:systemd-packaged-unit-effects".providerModule == null;
  assert desired.realization.source.artifact == artifact;
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
  assert builtins.length evaluation.config.systemd.providerUnitPlans == 1;
  assert !(desired.realization ? revision_receipt);
  assert successStatus.template == "0 2";
  assert searchPath.template != "";
  assert !(lib.hasInfix "/nix/store/" searchPath.template);
  assert builtins.length (builtins.attrNames searchPath.substitutions) == 2;
  assert !invalidUnitName.success; true
