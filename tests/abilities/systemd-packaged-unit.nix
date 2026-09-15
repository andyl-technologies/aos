##! Fixed-point evaluation of the systemd-owned packaged-unit provider.
{
  lib,
  pkgs,
}: let
  interfaceModule = ../../pkgs/system/_systemd-abilities.nix;
  providerModule = ../../pkgs/system/_systemd-provider.nix;
  artifact = lib.abilities.packageOutput {};
  artifactLocatorFor = selector:
    if (selector._type or null) != "aos-package-output-selector"
    then throw "provider attempted to resolve a materialized artifact reference"
    else {
      artifactReference = {
        _type = "aos-artifact-reference";
        content = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        store_path = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-example";
        nar_hash = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        closure = "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
      };
      path = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-example";
    };
  declaration =
    (import interfaceModule {inherit lib;}).config.aos.abilities.interfaces.systemd-packaged-unit;
  identity = lib.abilities.interfaceIdentity (
    lib.abilities.interfaceDocumentFromDeclaration declaration
  );
  consumerModuleFor = unitFile: {
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
      modules = [
        lib.abilities.module
        ../../modules/systemd/system.nix
        {
          config.aos.abilities = {
            environment = {
              authority = "test";
              key = "systemd-packaged-unit";
              stage = "host";
            };
            inherit bindings;
          };
        }
      ];
      packageModules = [
        {
          name = "systemd";
          module = {
            imports = [interfaceModule providerModule];
            config.aos.abilities.instances.manager = {};
          };
        }
        {
          name = "consumer";
          module = consumerModule;
        }
      ];
      specialArgs = {
        packageName = "systemd";
        inherit pkgs;
        provenance = {
          dependencyOwnersOfAttr = _: _: [];
          ownerOfListAttr = _: _: _: "@test";
        };
        inherit artifactLocatorFor;
      };
    };

  pending = evaluate (consumerModuleFor "lib/systemd/system/example.service") baseBindings;
  effectsChild = builtins.head (builtins.attrValues pending.config.aos.abilities.compositionPendingRequests);
  resolvedBindings = baseBindings
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
  desired = builtins.head (builtins.attrValues abilities.desiredResources);
  dependencyReference = abilities.compositionOutputs."consumer:unit".unit-resource.value;
  deferredDependency = {
    _type = "aos-request-output-reference";
    request = "consumer:unit";
    output = "unit-resource";
  };
  targetResource = desired // {
    value = desired.value // {
      dependencies = desired.value.dependencies // {after = [deferredDependency];};
    };
  };
  prerequisiteResource = desired // {
    value = desired.value // {
      prerequisites = [deferredDependency];
    };
  };
  composeFor = resolvedResources: compositionOutputs: resource: let
    provider = import providerModule {
      inherit lib pkgs artifactLocatorFor;
      packageName = "systemd";
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
  missingReference = dependencyReference // {
    resource = dependencyReference.resource // {key = "missing";};
  };
  missingResource = builtins.tryEval (builtins.deepSeq (
      composeFor abilities.resolvedResources abilities.compositionOutputs (
        targetResource
        // {
          value = targetResource.value // {
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
          value = targetResource.value // {
            dependencies = targetResource.value.dependencies // {
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
          value = targetResource.value // {
            dependencies = targetResource.value.dependencies // {
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
  assert desired.realization.source.artifact.store_path == "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-example";
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
  assert declaration.lifecycle.releasesEphemeralOnDisable;
  assert declaration.methods.remove.semantics.requiredTargetAccess == "exclusive-write";
  assert declaration.methods.remove.semantics.stopsProvider;
  assert !(declaration.methods.remove.outputs ? retained-resource);
  assert lib.hasInfix "@@AOS_SYSTEMD_SUBSTITUTION:" after.template;
  assert builtins.attrValues after.substitutions == [
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
