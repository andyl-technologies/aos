##! tests/abilities/authoring-conformance.nix - Shared corpus Nix checks.
{
  pkgs,
  lib,
}: let
  corpus = import ./conformance/corpus.nix;
  corpusFile = builtins.toFile "aos-ability-authoring-conformance-v1.json" (builtins.toJSON corpus);

  invalidRefinementDeclarations =
    builtins.map (
      schema: builtins.tryEval (builtins.deepSeq schema true)
    ) [
      (lib.abilities.schemas.refined {
        value = lib.abilities.schemas.integer {
          minimum = 0;
          maximum = 10;
        };
        constraints = [
          {
            kind = "string-pattern";
            pattern = "[0-9]+";
          }
        ];
      })
      (lib.abilities.schemas.refined {
        value = lib.abilities.schemas.string {
          maxLength = 16;
          syntax = null;
        };
        constraints = [
          {
            kind = "map-keys-pattern";
            pattern = "[a-z]+";
          }
        ];
      })
      (lib.abilities.schemas.refined {
        value = lib.abilities.schemas.boolean;
        constraints = [
          {
            kind = "minimum-size";
            minimum = 1;
          }
        ];
      })
      (lib.abilities.schemas.refined {
        value = lib.abilities.schemas.string {
          maxLength = 4;
          syntax = null;
        };
        constraints = [
          {
            kind = "minimum-size";
            minimum = 5;
          }
        ];
      })
      (lib.abilities.schemas.refined {
        value = lib.abilities.schemas.record {
          fields = {
            enabled = lib.abilities.schemas.boolean;
            names = lib.abilities.schemas.list {
              element = lib.abilities.schemas.string {
                maxLength = 16;
                syntax = null;
              };
              maxItems = 8;
            };
          };
          optional = [];
        };
        constraints = [
          {
            kind = "unique-at";
            path = ["missing"];
          }
        ];
      })
      (lib.abilities.schemas.refined {
        value = lib.abilities.schemas.record {
          fields.enabled = lib.abilities.schemas.boolean;
          optional = [];
        };
        constraints = [
          {
            kind = "unique-at";
            path = ["enabled"];
          }
        ];
      })
      (lib.abilities.schemas.refined {
        value = lib.abilities.schemas.record {
          fields.enabled = lib.abilities.schemas.boolean;
          optional = [];
        };
        constraints = [
          {
            kind = "structured-document";
            format_field = "enabled";
            document_field = "missing";
          }
        ];
      })
      (lib.abilities.schemas.refined {
        value = lib.abilities.schemas.record {
          fields = {
            allowed = lib.abilities.schemas.list {
              element = lib.abilities.schemas.string {
                maxLength = 16;
                syntax = null;
              };
              maxItems = 8;
            };
            requested = lib.abilities.schemas.list {
              element = lib.abilities.schemas.string {
                maxLength = 16;
                syntax = null;
              };
              maxItems = 8;
            };
            policy = lib.abilities.schemas.taggedUnion {
              tag = "kind";
              variants = {
                bounded = lib.abilities.schemas.record {
                  fields = {
                    kind = lib.abilities.schemas.enum ["bounded"];
                    limit = lib.abilities.schemas.integer {
                      minimum = 0;
                      maximum = 5;
                    };
                  };
                  optional = [];
                };
                extended = lib.abilities.schemas.record {
                  fields = {
                    kind = lib.abilities.schemas.enum ["extended"];
                    limit = lib.abilities.schemas.integer {
                      minimum = 0;
                      maximum = 10;
                    };
                  };
                  optional = [];
                };
              };
            };
          };
          optional = [];
        };
        constraints = [
          {
            kind = "subset-unless";
            subset = ["requested"];
            superset = ["allowed"];
            unless_path = ["policy" "limit"];
            unless_equals = 8;
          }
        ];
      })
    ];

  unique = values:
    builtins.length values
    == builtins.length (builtins.attrNames (builtins.listToAttrs (builtins.map (value: {
        name = value;
        value = true;
      })
      values)));

  portableRecordType = lib.abilities.types.record {
    fields = {
      enabled = {
        type = lib.abilities.types.boolean;
        default = true;
        description = "Whether the portable record is enabled.";
      };
      mode = lib.abilities.types.enum ["active" "passive"];
      name = lib.abilities.types.string {
        maxLength = 32;
        syntax = "local-key-v1";
      };
    };
  };
  portableRecordEvaluation = lib.evalModules {
    modules = [
      {
        options.testRecord = lib.mkOption {
          type = portableRecordType;
        };
        config.testRecord = {
          mode = "active";
          name = "example";
        };
      }
    ];
  };
  invalidPortableRecord = builtins.tryEval (builtins.deepSeq
    (lib.evalModules {
      modules = [
        {
          options.testRecord = lib.mkOption {
            type = portableRecordType;
          };
          config.testRecord = {
            mode = "invalid";
            name = "example";
          };
        }
      ];
    })
    .config
    .testRecord
    true);
  optionalRecordType = lib.abilities.types.record {
    fields = {
      omitted = {
        type = lib.abilities.types.string {
          maxLength = 32;
          syntax = null;
        };
        optional = true;
      };
      explicitNull = lib.abilities.types.optional lib.abilities.types.boolean;
      defaulted = {
        type = lib.abilities.types.boolean;
        default = true;
      };
    };
  };
  optionalRecordEvaluation = lib.evalModules {
    modules = [
      {
        options.test = lib.mkOption {type = optionalRecordType;};
        config.test.explicitNull = null;
      }
    ];
  };
  invalidOptionalRecord = builtins.tryEval (builtins.deepSeq
    (lib.evalModules {
      modules = [
        {
          options.test = lib.mkOption {type = optionalRecordType;};
          config.test = {
            explicitNull = null;
            unknown = true;
          };
        }
      ];
    })
    .config
    .test
    true);

  taggedVariant = lib.abilities.types.record {
    fields = {
      kind = lib.abilities.types.enum ["enabled"];
      settings = lib.abilities.types.record {
        fields.flag = {
          type = lib.abilities.types.boolean;
          default = true;
          description = "Whether the tagged variant is enabled.";
        };
      };
    };
  };
  authoredTaggedUnion = lib.abilities.types.taggedUnion {
    tag = "kind";
    variants.enabled = taggedVariant;
  };
  taggedUnionEvaluation = lib.evalModules {
    modules = [
      {
        options.test = lib.mkOption {type = authoredTaggedUnion;};
        config.test = {
          kind = "enabled";
          settings = {};
        };
      }
    ];
  };
  invalidTaggedUnion = builtins.tryEval (builtins.deepSeq
    (lib.evalModules {
      modules = [
        {
          options.test = lib.mkOption {type = authoredTaggedUnion;};
          config.test = {
            kind = "enabled";
            settings.unknown = true;
          };
        }
      ];
    })
    .config
    .test
    true);
  decodedRecordType = lib.abilities.types.fromSchema (lib.abilities.schemas.record {
    fields.enabled = lib.abilities.schemas.boolean;
    optional = [];
  });
  invalidDecodedRecord = builtins.tryEval (builtins.deepSeq
    (lib.evalModules {
      modules = [
        {
          options.test = lib.mkOption {type = decodedRecordType;};
          config.test = {
            enabled = true;
            unknown = true;
          };
        }
      ];
    })
    .config
    .test
    true);
  invalidResourceReference = builtins.tryEval (builtins.deepSeq
    (lib.evalModules {
      modules = [
        {
          options.test = lib.mkOption {type = lib.abilities.types.resourceReference;};
          config.test = {
            _type = "aos-resource-reference";
            interface = {
              name = "aos.test.resource";
              abi = 1;
              descriptor = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
              unknown = true;
            };
            resource = {
              provider = plainIdentity;
              key = "resource";
            };
            operations = [];
            lifetime = "instance";
          };
        }
      ];
    })
    .config
    .test
    true);
  executableInterface = lib.abilities.declareInterface {
    name = "aos.test.executable";
    abi = 1;
    description = "Accepts a symbolic executable reference for authoring conformance.";
    requestType = lib.abilities.types.record {
      fields.executable = lib.abilities.types.executableReference;
    };
    outputs = {};
    methods = {};
    lifecycle = {
      persistentDeleteMethod = null;
    };
    aggregation = {
      scope = "provider-instance";
      key = "slot";
      rejectSlotCollisions = true;
      mergeContract = null;
      controllerGroup = "executable";
    };
  };
  executableIdentity = lib.abilities.interfaceIdentity (
    lib.abilities.interfaceDocumentFromDeclaration executableInterface
  );
  crossTargetInterface =
    executableInterface
    // {
      name = "aos.test.cross-target";
      description = "Provides the target resource for a cross-interface method.";
    };
  crossSourceInterface =
    executableInterface
    // {
      name = "aos.test.cross-source";
      description = "Invokes a method against a separately declared resource interface.";
      methods.invoke = {
        description = "Invokes the separately declared target resource.";
        semantics = {
          requiredTargetAccess = "exclusive-write";
          stopsProvider = false;
        };
        parameters = lib.abilities.types.boolean;
        targetResource = crossTargetInterface.name;
        outputs.observed = {
          description = "Carries evidence captured during observation.";
          schema = lib.abilities.types.boolean;
          phase = "observation";
          visibility = "protected";
          lifetime = "attempt";
        };
        permittedOperations = ["invoke"];
        guarantees = [];
        outcome = {
          completionEvidence = lib.abilities.types.boolean;
          observationEvidence = lib.abilities.types.boolean;
          supportsRejectedBeforeEffect = true;
          indeterminate = "reconcile";
        };
      };
    };
  crossTargetEvaluation = lib.evalModules {
    modules = [
      lib.abilities.module
      {
        config.aos.abilities = {
          environment = plainIdentity.environment;
          interfaces = {
            "authoring:source" = crossSourceInterface;
            "authoring:target" = crossTargetInterface;
          };
        };
      }
    ];
  };

  revisionValueType = lib.abilities.types.record {
    fields = {
      enabled = lib.abilities.types.boolean;
      artifact = {
        type = lib.abilities.types.artifactReference;
        optional = true;
      };
    };
  };
  revisionInterface =
    crossSourceInterface
    // {
      name = "aos.test.revision-resource";
      description = "Exercises centrally derived resource revisions.";
      requestType = revisionValueType;
      methods =
        crossSourceInterface.methods
        // {
          invoke =
            crossSourceInterface.methods.invoke
            // {
              targetResource = "aos.test.revision-resource";
            };
        };
      lifecycle = crossSourceInterface.lifecycle;
    };
  revisionInterfaceIdentity = lib.abilities.interfaceIdentity (
    lib.abilities.interfaceDocumentFromDeclaration revisionInterface
  );
  revisionEvaluation = {
    value ? {enabled = true;},
    realization ? true,
    implementation ? "primary",
    desiredType ? lib.abilities.types.boolean,
    lifetime ? "instance",
    slot ? "resource",
    unrelated ? false,
    requirementDescription ? "Requires the resource revision conformance fixture.",
  }: let
    implementationName = "authoring:${implementation}";
  in
    (lib.evalModules {
      modules = [
        lib.abilities.module
        {
          config.aos.abilities = {
            environment = plainIdentity.environment;
            interfaces."authoring:resource" = revisionInterface;
            implementations.${implementationName} = {
              description = "Provides the resource revision conformance fixture.";
              interface = "authoring:resource";
              methods = ["invoke"];
              requirements.lower = {
                alias = "lower";
                description = requirementDescription;
                accepted_interfaces = [revisionInterfaceIdentity];
                methods = ["invoke"];
                guarantees = [];
                strength = "required";
                fallback = null;
              };
              inherit desiredType;
            };
            instances."authoring:provider" = {
              implementation = implementationName;
              configuration = {};
            };
            requirementTemplates."authoring:resource" = {
              description = "Requires the resource revision conformance fixture.";
              interface = revisionInterfaceIdentity.name;
              inherit (revisionInterfaceIdentity) abi descriptor;
              methods = ["invoke"];
            };
            requests =
              {
                "authoring:resource" = {
                  requirement = "authoring:resource";
                  consumer = "authoring:provider";
                  parameters = value;
                };
              }
              // lib.optionalAttrs unrelated {
                "authoring:unrelated" = {
                  requirement = "authoring:resource";
                  consumer = "authoring:provider";
                  parameters.enabled = false;
                };
              };
            bindings =
              {
                "authoring:controller" = {
                  request = "authoring:resource";
                  implementation = implementationName;
                  providerInstance = "authoring:provider";
                  inherit slot;
                };
              }
              // lib.optionalAttrs unrelated {
                "authoring:unrelated-controller" = {
                  request = "authoring:unrelated";
                  implementation = implementationName;
                  providerInstance = "authoring:provider";
                  slot = "unrelated";
                };
              };
            desiredResources =
              {
                "authoring:resource" = {
                  resource = {
                    provider = revisionProviderIdentity;
                    key = "resource";
                  };
                  kind = revisionInterface.name;
                  controller = "authoring:controller";
                  inherit lifetime;
                  inherit value realization;
                };
              }
              // lib.optionalAttrs unrelated {
                "authoring:unrelated" = {
                  resource = {
                    provider = revisionProviderIdentity;
                    key = "unrelated";
                  };
                  kind = revisionInterface.name;
                  controller = "authoring:unrelated-controller";
                  lifetime = "instance";
                  value.enabled = false;
                  realization = true;
                };
              };
          };
        }
      ];
    })
    .config
    .aos
    .abilities;
  primaryRevisionEvaluation = revisionEvaluation {};
  changedValueRevisionEvaluation = revisionEvaluation {value.enabled = false;};
  changedRealizationRevisionEvaluation = revisionEvaluation {realization = false;};
  changedImplementationRevisionEvaluation = revisionEvaluation {implementation = "secondary";};
  changedLifetimeRevisionEvaluation = revisionEvaluation {lifetime = "persistent";};
  changedControllerRevisionEvaluation = revisionEvaluation {slot = "alternate";};
  unrelatedRevisionEvaluation = revisionEvaluation {unrelated = true;};
  requirementProseRevisionEvaluation = revisionEvaluation {
    requirementDescription = "Reworded lower-interface requirement documentation.";
  };
  invalidRealizationEvaluation = builtins.tryEval (builtins.deepSeq
    (revisionEvaluation {realization = "invalid";}).resolvedResources
    true);
  missingDesiredTypeEvaluation = builtins.tryEval (builtins.deepSeq
    (revisionEvaluation {desiredType = null;}).resolvedResources
    true);

  semanticArtifact = storePath: narHash:
    lib.abilities.artifactReference {
      content = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
      storePath = storePath;
      narHash = narHash;
      closure = "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
    };
  artifactRevision = storePath: narHash:
    (revisionEvaluation {
      value = {
        enabled = true;
        artifact = semanticArtifact storePath narHash;
      };
    })
    .resolvedResources
    ."authoring:resource"
    .revision;
  artifactRevisionA = artifactRevision "/nix/store/aaaaaaaa-source" "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
  artifactRevisionRelocated = artifactRevision "/nix/store/dddddddd-source" "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
  artifactRevisionChanged = artifactRevision "/nix/store/aaaaaaaa-source" "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
  missingCrossTarget = builtins.tryEval (builtins.deepSeq
    (lib.evalModules {
      modules = [
        lib.abilities.module
        {
          config.aos.abilities = {
            environment = plainIdentity.environment;
            interfaces."authoring:source" = crossSourceInterface;
          };
        }
      ];
    })
    .config
    .aos
    .abilities
    .interfaces
    true);
  executableModule = {
    entryPoint,
    selector,
    description ? "Accepts a symbolic executable reference for authoring conformance.",
  }: {
    config.aos.abilities = {
      environment = plainIdentity.environment;
      interfaces."authoring:executable" = executableInterface // {inherit description;};
      instances."authoring:consumer" = {};
      requirementTemplates."authoring:executable" = {
        description = "Requires the executable-reference conformance interface.";
        interface = executableIdentity.name;
        inherit (executableIdentity) abi descriptor;
      };
      requests."authoring:executable" = {
        requirement = "authoring:executable";
        consumer = "authoring:consumer";
        parameters.executable = {
          artifact = selector;
          entry_point = entryPoint;
          arguments = [
            "--serve"
            (lib.abilities.resultOf "configuration" "path")
          ];
        };
      };
    };
  };
  validExecutableRequest = lib.evalModules {
    modules = [
      lib.abilities.module
      (executableModule {
        entryPoint = "bin/server";
        selector = selfOutput;
      })
    ];
  };

  canonicalAbilityEvaluation = lib.evalModules {
    modules = [
      lib.abilities.module
      {
        config.aos.abilities.requirementTemplates.database = {
          description = "Requires the database lifecycle methods used by this conformance case.";
          interface = "aos.test.database";
          abi = 1;
          descriptor = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
          methods = ["start" "stop"];
        };
      }
    ];
  };
  invalidCanonicalAbility = builtins.tryEval (builtins.deepSeq
    (lib.evalModules {
      modules = [
        lib.abilities.module
        {
          config.aos.abilities.requirementTemplates.database = {
            description = "Malformed requirement used to exercise strict nested rejection.";
            interface = "aos.test.database";
            abi = 1;
            descriptor = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
            unknown = true;
          };
        }
      ];
    })
    .config
    .aos
    .abilities
    .requirementTemplates
    true);

  selfOutput = lib.abilities.packageOutput {};
  namedOutput = lib.abilities.packageOutput {
    package = "aos";
    output = "packageRuntime";
  };
  implementationInterface = lib.abilities.declareInterface {
    name = "aos.test.symbolic-artifact";
    abi = 1;
    description = "Exercises package-local selector qualification.";
    requestType = lib.abilities.types.boolean;
    configurationType = lib.abilities.types.boolean;
    outputs.flag = {
      description = "Publishes the selected test flag.";
      schema = lib.abilities.types.boolean;
      phase = "planning";
      visibility = "protected";
      lifetime = "instance";
    };
    methods = {};
    lifecycle = {
      persistentDeleteMethod = null;
    };
    guarantees = [];
    aggregation = {
      scope = "provider-instance";
      key = "slot";
      rejectSlotCollisions = true;
      mergeContract = null;
      controllerGroup = "symbolic-artifact";
    };
    requiredFeatures = [];
  };
  implementation = {
    description = "Provides the selector qualification test interface.";
    interface = "test";
    methods = [];
    guarantees = [];
    requirements = {};
    artifact = selfOutput;
    artifacts = [];
    providerModule = {
      artifact = selfOutput;
      path = "share/abilities/provider.nix";
    };
    desiredType = lib.abilities.types.boolean;
    requiredFeatures = [];
    compose = context: context;
    transition = context: context;
    provide = null;
    handlerDescriptor = null;
    state_format = null;
  };
  evaluateImplementation = implementation:
    (lib.evalModules {
      modules = [lib.abilities.module];
      packageModules = [
        {
          name = "authoring";
          module.config.aos.abilities = {
            interfaces.test = implementationInterface;
            implementations.test = implementation;
          };
        }
      ];
    })
    .config
    .aos
    .abilities;
  rejectsImplementation = implementation:
    !(builtins.tryEval (builtins.deepSeq (evaluateImplementation implementation) true)).success;
  authoredGuarantee = lib.abilities.guarantee {
    name = "aos.guarantee.authoring-test";
    version = 1;
    semantics = "successful completion proves the authoring fixture contract";
    description = "Documents the authoring fixture guarantee.";
  };
  proseChangedGuarantee =
    authoredGuarantee
    // {
      description = "Documents the same authoring guarantee with revised prose.";
    };
  semanticsChangedGuarantee =
    authoredGuarantee
    // {
      semantics = "successful completion proves a different authoring fixture contract";
    };
  guaranteeReferenceDeclaration =
    implementationInterface
    // {
      guarantees = ["authoring"];
    };
  guaranteeReferenceEvaluation = lib.evalModules {
    modules = [lib.abilities.module];
    packageModules = [
      {
        name = "authoring";
        module.config.aos.abilities = {
          guarantees.authoring = authoredGuarantee;
          interfaces.test = guaranteeReferenceDeclaration;
        };
      }
    ];
  };
  projectAbilityConfig = packageName: evaluation:
    (lib.abilities.projectPackage {
      inherit packageName;
      version = "1";
      evaluated = evaluation.config.aos.abilities;
    })
    .value;
  missingGuaranteeReferenceEvaluation = lib.evalModules {
    modules = [lib.abilities.module];
    packageModules = [
      {
        name = "missing";
        module.config.aos.abilities.interfaces.test = guaranteeReferenceDeclaration;
      }
    ];
  };
  missingGuaranteeReference = builtins.tryEval (builtins.deepSeq (
      projectAbilityConfig "missing" missingGuaranteeReferenceEvaluation
    )
    true);
  conflictingGuaranteeCatalog = builtins.tryEval (builtins.deepSeq (
      (lib.evalModules {
        modules = [
          lib.abilities.module
          {config.aos.abilities.guarantees.authoring = authoredGuarantee;}
          {config.aos.abilities.guarantees.authoring = proseChangedGuarantee;}
        ];
      })
      .config
      .aos
      .abilities
      .guarantees
    )
    true);
  expectedGuaranteeDescriptor = lib.abilities.descriptorFor "aos.ability.execution-guarantee/v1" {
    name = authoredGuarantee.name;
    version = authoredGuarantee.version;
    semantics = authoredGuarantee.semantics;
  };
  guaranteeReferenceProjection = projectAbilityConfig "authoring" guaranteeReferenceEvaluation;
  sharedInterfaceIdentity = lib.abilities.interfaceIdentity (
    lib.abilities.interfaceDocumentFromDeclaration implementationInterface
  );
  sharedImplementationEvaluation = lib.evalModules {
    modules = [
      lib.abilities.module
      {config.aos.abilities.interfaces.shared = implementationInterface;}
    ];
    packageModules = [
      {
        name = "authoring";
        module.config.aos.abilities.implementations.shared =
          implementation
          // {
            interface = sharedInterfaceIdentity;
          };
      }
    ];
  };
  sharedImplementationProjection = projectAbilityConfig "authoring" sharedImplementationEvaluation;
  serviceManagement = lib.abilities.interfaces.serviceManagement;
  serviceGuarantees = serviceManagement.guaranteeAliases;
  coreGuaranteeProviderEvaluation = lib.evalModules {
    modules = [lib.abilities.module];
    packageModules = [
      {
        name = "core-guarantee-provider";
        module.config.aos.abilities.implementations = {
          lifecycle =
            implementation
            // {
              description = "Implements the canonical service lifecycle with exact template reuse.";
              interface = serviceManagement.interfaces.lifecycle.identity;
              methods = ["observe"];
              guarantees = [serviceGuarantees.templateExactReuse];
            };
          conditions =
            implementation
            // {
              description = "Implements the canonical provider-neutral service conditions.";
              interface = serviceManagement.interfaces.conditions.identity;
              methods = ["observe"];
              guarantees = builtins.attrValues serviceGuarantees.condition;
            };
        };
      }
    ];
  };
  coreGuaranteeProviderProjection =
    projectAbilityConfig "core-guarantee-provider" coreGuaranteeProviderEvaluation;
  sharedImplementationFixedPoint = lib.evalModules {
    modules = [
      lib.abilities.module
      {
        config.aos.abilities = {
          environment = plainIdentity.environment;
          interfaces.shared = implementationInterface;
        };
      }
    ];
    packageModules = [
      {
        name = "authoring";
        module.config.aos.abilities = {
          implementations.shared =
            implementation
            // {
              interface = sharedInterfaceIdentity;
            };
          instances.shared = {
            implementation = "shared";
            configuration = true;
          };
        };
      }
    ];
  };
  packageModuleFor = package: {
    name = package;
    module.config.aos.abilities = {
      guarantees.authoring = authoredGuarantee;
      interfaces.test = implementationInterface // {guarantees = ["authoring"];};
      implementations.test =
        implementation
        // {
          guarantees = ["authoring"];
          provide = context: context;
        };
    };
  };
  combinedPackageEvaluation = lib.evalModules {
    modules = [lib.abilities.module];
    packageModules = [
      (packageModuleFor "alpha")
      (packageModuleFor "beta")
    ];
  };
  instanceIdentityEvaluation = lib.evalModules {
    inherit lib;
    modules = [
      lib.abilities.module
      {
        config.aos.abilities = {
          environment = {
            authority = "fleet";
            key = "host";
            stage = "host";
          };
          instances."demo:server" = {};
        };
      }
    ];
  };
  derivedInstanceIdentity =
    instanceIdentityEvaluation.config.aos.abilities.instanceIdentities."demo:server";
  forgedSelector = package: output: {
    _type = "aos-package-output-selector";
    inherit package output;
  };
  handlerImplementation = artifact: entryPoint: {
    inherit (implementation) description interface methods guarantees requirements artifacts desiredType requiredFeatures;
    artifact = artifact;
    compose = null;
    transition = null;
    provide = null;
    providerModule = null;
    state_format = null;
    handlerDescriptor = {
      inherit artifact entryPoint;
      arguments = lib.abilities.types.boolean;
      result = lib.abilities.types.boolean;
    };
  };
  rejectsAbilityModule = module:
    !(builtins.tryEval (builtins.deepSeq
      (lib.evalModules {
        modules = [lib.abilities.module module];
      })
      .config
      .aos
      .abilities
      true))
    .success;
  plainIdentity = {
    environment = {
      authority = "deployment";
      key = "test";
      stage = "host";
    };
    key = "instance";
  };
  revisionIdentityEvaluation = lib.evalModules {
    modules = [
      lib.abilities.module
      {
        config.aos.abilities = {
          environment = plainIdentity.environment;
          instances."authoring:provider" = {};
        };
      }
    ];
  };
  revisionProviderIdentity =
    revisionIdentityEvaluation.config.aos.abilities.instanceIdentities."authoring:provider";
  invalidPackageOutputField = builtins.tryEval (builtins.deepSeq
    (lib.abilities.packageOutput {unknown = true;})
    true);
  invalidPackageOutputKey = builtins.tryEval (builtins.deepSeq
    (lib.abilities.packageOutput {package = "bad/package";})
    true);

  checkAcceptedCase = case: let
    evaluated = builtins.tryEval (builtins.deepSeq
      (lib.abilities.schemas.checkValue case.schema case.value)
      case.value);
  in
    if case.expected.outcome == "accept"
    then evaluated.success && evaluated.value == case.expected.value
    else !evaluated.success;

  caseIds = builtins.map (case: case.id) corpus.cases;
  directFixture = pkgs.mkDerivation {
    pname = "aos-ability-authoring-direct-fixture";
    version = "1";
    src = null;
    phases = [
      {
        name = "install";
        script = ''
          mkdir -p "$out/lib"
          cp -R ${../../lib}/. "$out/lib/"
          cp ${./conformance/direct.nix} "$out/direct.nix"
        '';
      }
    ];
  };
in
  assert corpus.schema == "aos.ability.authoring-conformance/v1";
  assert unique caseIds;
  assert builtins.attrNames (lib.abilities.module {config = null;}).options == ["aos"];
  assert canonicalAbilityEvaluation.config.aos.abilities.requirementTemplates.database
  == {
    abi = 1;
    description = "Requires the database lifecycle methods used by this conformance case.";
    descriptor = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    fallback = null;
    guarantees = [];
    interface = "aos.test.database";
    methods = ["start" "stop"];
    strength = "required";
  };
  assert !invalidCanonicalAbility.success;
  assert optionalRecordEvaluation.config.test
  == {
    defaulted = true;
    explicitNull = null;
  };
  assert !invalidOptionalRecord.success;
  assert selfOutput
  == {
    _type = "aos-package-output-selector";
    output = "out";
    package = "self";
  };
  assert namedOutput.output == "packageRuntime";
  assert !invalidPackageOutputField.success;
  assert !invalidPackageOutputKey.success;
  assert (evaluateImplementation implementation).implementations."authoring:test".interface == "authoring:test";
  assert builtins.attrNames combinedPackageEvaluation.config.aos.abilities.implementations == ["alpha:test" "beta:test"];
  assert builtins.isFunction combinedPackageEvaluation.config.aos.abilities.implementations."alpha:test".provide;
  assert derivedInstanceIdentity.environment
  == {
    authority = "fleet";
    key = "host";
    stage = "host";
  };
  assert lib.hasPrefix "instance-" derivedInstanceIdentity.key;
  assert builtins.stringLength derivedInstanceIdentity.key == 73;
  assert lib.abilities.types.localKey.check derivedInstanceIdentity.key;
  assert combinedPackageEvaluation.config.aos.abilities.implementations."alpha:test".package == "alpha";
  assert combinedPackageEvaluation.config.aos.abilities.implementations."alpha:test".interface == "alpha:test";
  assert rejectsImplementation (implementation // {artifact = {};});
  assert rejectsImplementation (implementation
    // {
      artifact = "/nix/store/00000000000000000000000000000000-artifact";
    });
  assert rejectsImplementation (implementation // {artifacts = [{}];});
  assert rejectsImplementation (implementation
    // {
      artifact = forgedSelector "bad/package" "out";
    });
  assert rejectsImplementation (implementation
    // {
      artifact = forgedSelector "self" "bad/output";
    });
  assert rejectsImplementation (implementation
    // {
      artifact = (forgedSelector "self" "out") // {unknown = true;};
    });
  assert rejectsImplementation (handlerImplementation {} "bin/handler");
  assert rejectsImplementation (handlerImplementation selfOutput "/bin/handler");
  assert rejectsImplementation (handlerImplementation selfOutput "");
  assert rejectsImplementation (handlerImplementation selfOutput "bin//handler");
  assert rejectsImplementation (handlerImplementation selfOutput "bin/./handler");
  assert rejectsImplementation (handlerImplementation selfOutput "bin/../handler");
  assert rejectsImplementation ((handlerImplementation selfOutput "bin/handler")
    // {
      handler.arguments = lib.abilities.schemas.boolean;
    });
  assert rejectsAbilityModule {
    config.aos.abilities.interfaces.test =
      implementationInterface
      // {
        lifecycle = implementationInterface.lifecycle // {unknown = true;};
      };
  };
  assert rejectsAbilityModule {
    config.aos.abilities = {
      interfaces.test = implementationInterface;
      implementations.test = implementation;
      environment = plainIdentity.environment;
      instances.test = {
        implementation = "test";
        configuration = "not-a-boolean";
      };
    };
  };
  assert rejectsAbilityModule {
    config.aos.abilities = {
      interfaces.test = implementationInterface;
      implementations.test = implementation;
      environment = plainIdentity.environment;
      instances.consumer = {};
      requirementTemplates.test = {
        description = "Requires the symbolic artifact test interface.";
        interface = executableIdentity;
        strength = "advisory";
        fallback.outputs.flag = "not-a-boolean";
      };
    };
  };
  assert rejectsAbilityModule {
    config.aos.abilities = {
      interfaces.test = implementationInterface;
      implementations.test = implementation;
      environment = plainIdentity.environment;
      instances.consumer = {};
      requirementTemplates.test = {
        description = "Requires the symbolic artifact test interface.";
        interface = executableIdentity;
      };
      requests.test = {
        requirement = "test";
        consumer = "consumer";
        parameters = "not-a-boolean";
      };
    };
  };
  assert rejectsAbilityModule {
    config.aos.abilities.bindings.test = {
      request = "test";
      implementation = "test";
      providerInstance = "bad/instance";
      slot = "test";
    };
  };
  assert rejectsAbilityModule {
    config.aos.abilities = {
      interfaces.test = implementationInterface;
      implementations.test = implementation;
      desiredResources.test = {
        kind = "aos.test.symbolic-artifact";
        controller = "test";
        lifetime = "instance";
        value = "not-a-boolean";
      };
    };
  };
  assert portableRecordEvaluation.config.testRecord
  == {
    enabled = true;
    mode = "active";
    name = "example";
  };
  assert taggedUnionEvaluation.config.test.settings.flag;
  assert !invalidTaggedUnion.success;
  assert !invalidDecodedRecord.success;
  assert !invalidResourceReference.success;
  assert validExecutableRequest.config.aos.abilities.requests."authoring:executable".parameters.executable.entry_point == "bin/server";
  assert !(authoredGuarantee ? descriptor);
  assert guaranteeReferenceEvaluation.config.aos.abilities.guarantees."authoring:authoring" == authoredGuarantee;
  assert guaranteeReferenceEvaluation.config.aos.abilities.interfaces."authoring:test".guarantees == ["authoring:authoring"];
  assert sharedImplementationEvaluation.config.aos.abilities.implementations."authoring:shared".interface
  == sharedInterfaceIdentity;
  assert sharedImplementationProjection.interfaces.shared == sharedInterfaceIdentity;
  assert (builtins.head sharedImplementationProjection.exports).interface == sharedInterfaceIdentity;
  assert coreGuaranteeProviderProjection.guarantees == {};
  assert builtins.map (provider: provider.name) coreGuaranteeProviderProjection.implementation.providers
  == ["conditions" "lifecycle"];
  assert builtins.map (guarantee: guarantee.name)
  (builtins.head coreGuaranteeProviderProjection.implementation.providers).guarantees
  == [
    "aos.guarantee.service-condition.kernel-argument"
    "aos.guarantee.service-condition.mandatory-access-control"
    "aos.guarantee.service-condition.path"
  ];
  assert builtins.map (guarantee: guarantee.name)
  (builtins.elemAt coreGuaranteeProviderProjection.implementation.providers 1).guarantees
  == ["aos.guarantee.service-template-exact-reuse"];
  assert sharedImplementationFixedPoint.config.aos.abilities.instances."authoring:shared".configuration;
  assert (builtins.head guaranteeReferenceProjection.interface_documents).document.interface.guarantees
  == [
    {
      name = authoredGuarantee.name;
      version = authoredGuarantee.version;
      descriptor = expectedGuaranteeDescriptor;
    }
  ];
  assert !missingGuaranteeReference.success;
  assert !conflictingGuaranteeCatalog.success;
  assert lib.abilities.guaranteeIdentity authoredGuarantee == lib.abilities.guaranteeIdentity proseChangedGuarantee;
  assert lib.abilities.guaranteeIdentity authoredGuarantee != lib.abilities.guaranteeIdentity semanticsChangedGuarantee;
  assert (builtins.head guaranteeReferenceProjection.interface_documents).document.interface.guarantees
  == [
    {
      name = authoredGuarantee.name;
      version = authoredGuarantee.version;
      descriptor = expectedGuaranteeDescriptor;
    }
  ];
  assert crossTargetEvaluation.config.aos.abilities.interfaces."authoring:source".methods.invoke.targetResource == crossTargetInterface.name;
  assert crossTargetEvaluation.config.aos.abilities.interfaces."authoring:source".methods.invoke.outputs.observed.phase == "observation";
  assert !missingCrossTarget.success;
  assert primaryRevisionEvaluation.instanceIdentities."authoring:provider"
  == revisionProviderIdentity;
  assert primaryRevisionEvaluation.resolvedResources."authoring:resource".resource
  == {
    provider = primaryRevisionEvaluation.instanceIdentities."authoring:provider";
    key = "resource";
  };
  assert primaryRevisionEvaluation.resolvedResources."authoring:resource".revision
  != changedValueRevisionEvaluation.resolvedResources."authoring:resource".revision;
  assert primaryRevisionEvaluation.resolvedResources."authoring:resource".revision
  != changedRealizationRevisionEvaluation.resolvedResources."authoring:resource".revision;
  assert primaryRevisionEvaluation.resolvedResources."authoring:resource".revision
  != changedImplementationRevisionEvaluation.resolvedResources."authoring:resource".revision;
  assert primaryRevisionEvaluation.resolvedResources."authoring:resource".revision
  != changedLifetimeRevisionEvaluation.resolvedResources."authoring:resource".revision;
  assert primaryRevisionEvaluation.resolvedResources."authoring:resource".revision
  != changedControllerRevisionEvaluation.resolvedResources."authoring:resource".revision;
  assert primaryRevisionEvaluation.resolvedResources."authoring:resource".revision
  == unrelatedRevisionEvaluation.resolvedResources."authoring:resource".revision;
  assert primaryRevisionEvaluation.resolvedResources."authoring:resource".revision
  == requirementProseRevisionEvaluation.resolvedResources."authoring:resource".revision;
  assert !invalidRealizationEvaluation.success;
  assert !missingDesiredTypeEvaluation.success;
  assert artifactRevisionA == artifactRevisionRelocated;
  assert artifactRevisionA != artifactRevisionChanged;
  assert rejectsAbilityModule (executableModule {
    entryPoint = "/bin/server";
    selector = selfOutput;
  });
  assert rejectsAbilityModule (executableModule {
    entryPoint = "bin/server";
    selector = selfOutput // {unknown = true;};
  });
  assert rejectsAbilityModule (executableModule {
    entryPoint = "bin/server";
    selector = selfOutput;
    description = "";
  });
  assert rejectsAbilityModule (executableModule {
    entryPoint = "bin/server";
    selector = selfOutput;
    description = builtins.concatStringsSep "" (builtins.genList (_: "x") 4097);
  });
  assert lib.abilities.types.schemaOf "portable record" portableRecordType
  == {
    fields = {
      enabled = {kind = "boolean";};
      mode = {
        kind = "string-enum";
        values = ["active" "passive"];
      };
      name = {
        kind = "string";
        max_length = 32;
        syntax = "local-key-v1";
      };
    };
    kind = "record";
    optional_fields = ["enabled"];
  };
  assert !invalidPortableRecord.success;
  assert builtins.all (result: !result.success) invalidRefinementDeclarations;
  assert builtins.all checkAcceptedCase corpus.cases;
    pkgs.mkDerivation {
      pname = "aos-ability-authoring-conformance-v1";
      version = "0";
      src = null;
      buildDeps = [pkgs.jq pkgs.nix pkgs.grep];
      phases = [
        {
          name = "check";
          script = ''
            export HOME="$TMPDIR/home"
            export NIX_STATE_DIR="$TMPDIR/nix-state"
            export NIX_CONF_DIR="$TMPDIR/nix-conf"
            mkdir -p "$HOME" "$NIX_STATE_DIR/profiles" "$NIX_CONF_DIR"

            rejection_cases="$TMPDIR/nix-rejections.jsonl"
            ${pkgs.jq}/bin/jq -c \
              '.cases[] | select(.expected.outcome == "reject")' \
              ${corpusFile} > "$rejection_cases"

            tested=0
            while IFS= read -r case_json; do
              case_id="$(printf '%s\n' "$case_json" | ${pkgs.jq}/bin/jq -r '.id')"
              expected_code="$(printf '%s\n' "$case_json" | ${pkgs.jq}/bin/jq -r '.expected.code')"

              if diagnostic="$(${pkgs.nix}/bin/nix-instantiate \
                --eval --strict --json \
                --argstr caseJson "$case_json" \
                --argstr system ${lib.escapeShellArg pkgs.stdenv.buildPlatform.system} \
                ${directFixture}/direct.nix 2>&1)"; then
                echo "ability authoring case '$case_id' unexpectedly succeeded" >&2
                exit 1
              fi

              markers="$(printf '%s\n' "$diagnostic" \
                | ${pkgs.grep}/bin/grep -o 'AOS_ABILITY_DIAGNOSTIC_V1\[[a-z0-9-]*\]' \
                | ${pkgs.coreutils}/bin/sort -u || true)"
              if [ "$markers" != "AOS_ABILITY_DIAGNOSTIC_V1[$expected_code]" ]; then
                echo "ability authoring case '$case_id' returned '$markers', expected '$expected_code'" >&2
                printf '%s\n' "$diagnostic" >&2
                exit 1
              fi

              tested=$((tested + 1))
            done < "$rejection_cases"

            if [ "$tested" -eq 0 ]; then
              echo "ability authoring corpus contains no direct Nix rejection cases" >&2
              exit 1
            fi

            mkdir -p "$out"
            cp ${corpusFile} "$out/corpus.json"
            echo PASS > "$out/result"
          '';
        }
      ];
    }
