##! lib/testing/abilities.nix - Pure ability authoring and wire fixtures.
{
  pkgs,
  lib,
}: let
  fails = value: !(builtins.tryEval (builtins.deepSeq value true)).success;

  interfaceDocument = import ../../tests/abilities/interface.nix {
    inherit (lib) abilities;
  };
  canonicalInterface = builtins.toJSON interfaceDocument;
  expectedInterface = builtins.readFile ../../tests/abilities/fixtures/interface.json;

  invalidNestedSchema = builtins.tryEval (builtins.deepSeq (
      lib.abilities.schemas.record {
        fields.bad = {
          kind = "string";
          max_length = 10;
          syntax = null;
          unexpected = true;
        };
        optional = [];
      }
    )
    true);

  validOptionalRecord =
    lib.abilities.schemas.checkValue
    (lib.abilities.schemas.record {
      fields = {
        enabled = lib.abilities.schemas.boolean;
        label = lib.abilities.schemas.string {
          maxLength = 16;
          syntax = null;
        };
      };
      optional = ["label"];
    })
    {enabled = true;};

  nestedSchema = count:
    builtins.foldl'
    (value: _: {
      kind = "optional";
      inherit value;
    })
    {kind = "boolean";}
    (builtins.genList (_: null) count);
  atLimitSchema = nestedSchema 63;
  overLimitSchema = nestedSchema 64;

  asciiControlMap =
    lib.abilities.schemas.checkValue
    (lib.abilities.schemas.map {
      keyMaxLength = 16;
      keySyntax = null;
      maxEntries = 1;
      value = lib.abilities.schemas.boolean;
    })
    (builtins.listToAttrs [
      {
        name = "\tkey";
        value = true;
      }
    ]);

  nonAsciiMap = builtins.listToAttrs [
    {
      name = "é";
      value = true;
    }
  ];

  testEnvironment = lib.abilities.environmentId {
    authority = "deployment";
    key = "test";
    stage = "host";
  };
  testInstanceId = lib.abilities.instanceId {
    environment = testEnvironment;
    key = "provider";
  };
  testInterface = {
    name = "aos.test.reference";
    abi = 1;
    descriptor = "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
  };

  guaranteeOrdering =
    builtins.map
    (value: "${value.name}:${builtins.toString value.version}")
    (lib.abilities.define {
      interface = "aos.test.ordering";
      abi = 1;
      requestSchema = lib.abilities.schemas.boolean;
      outputs = {};
      methods = {};
      lifecycle = {
        stableResourceIdentity = true;
        releasesEphemeralOnDisable = true;
        retainsPersistentByDefault = true;
        persistentDeleteMethod = null;
      };
      guarantees = [
        {
          name = "aos.zz";
          version = 1;
          descriptor = "sha256:5555555555555555555555555555555555555555555555555555555555555555";
        }
        {
          name = "aos.a.long";
          version = 1;
          descriptor = "sha256:4444444444444444444444444444444444444444444444444444444444444444";
        }
        {
          name = "aos.a";
          version = 10;
          descriptor = "sha256:3333333333333333333333333333333333333333333333333333333333333333";
        }
        {
          name = "aos.a";
          version = 2;
          descriptor = "sha256:2222222222222222222222222222222222222222222222222222222222222222";
        }
      ];
      aggregation = {
        scope = "provider-instance";
        key = "authorized-slot";
        rejectSlotCollisions = true;
        mergeContract = null;
        controllerGroup = "ordering";
      };
      requires = {};
      ownsResourceKinds = [];
      handler = "ordering-handler";
    }).guarantees;

  methodFamilyInterface = operationFamily:
    lib.abilities.define {
      interface = "aos.test.method-family";
      abi = 1;
      requestSchema = lib.abilities.schemas.boolean;
      outputs = {};
      methods.run = {
        inherit operationFamily;
        parameters = lib.abilities.schemas.boolean;
        targetResource = "aos.test.method-family";
        outputs = {};
        permittedOperations = ["run"];
        guarantees = [];
        outcome = {
          completionEvidence = lib.abilities.schemas.boolean;
          observationEvidence = lib.abilities.schemas.boolean;
          supportsRejectedBeforeEffect = true;
          indeterminate = "reconcile";
        };
      };
      lifecycle = {
        stableResourceIdentity = true;
        releasesEphemeralOnDisable = true;
        retainsPersistentByDefault = true;
        persistentDeleteMethod = null;
      };
      guarantees = [];
      aggregation = {
        scope = "provider-instance";
        key = "authorized-slot";
        rejectSlotCollisions = true;
        mergeContract = null;
        controllerGroup = "method-family";
      };
      requires = {};
      ownsResourceKinds = ["aos.test.method-family"];
      handler = "method-family-handler";
    };
  acceptedMethodImageFamily =
    (methodFamilyInterface {
      kind = "image-rollout";
      action = "retain";
    }).methods.run.operation_family;
  invalidMethodImageFamily = builtins.tryEval (builtins.deepSeq (
      (methodFamilyInterface {
        kind = "image-rollout";
        action = "unknown";
      }).methods.run.operation_family
    )
    true);

  configurationExport = configurationSchema:
    lib.abilities.define {
      interface = "aos.test.configuration";
      abi = 1;
      requestSchema = lib.abilities.schemas.boolean;
      inherit configurationSchema;
      outputs = {};
      methods = {};
      lifecycle = {
        stableResourceIdentity = true;
        releasesEphemeralOnDisable = true;
        retainsPersistentByDefault = true;
        persistentDeleteMethod = null;
      };
      guarantees = [];
      aggregation = {
        scope = "provider-instance";
        key = "authorized-slot";
        rejectSlotCollisions = true;
        mergeContract = null;
        controllerGroup = "configuration";
      };
      requires = {};
      ownsResourceKinds = [];
      handler = "configuration-handler";
    };
  literalConfigurationSchema = lib.abilities.schemas.record {
    fields.ports = lib.abilities.schemas.list {
      element = lib.abilities.schemas.integer {
        minimum = 1024;
        maximum = 65535;
      };
      maxItems = 8;
    };
    optional = [];
  };
  invalidConfigurationSchema =
    builtins.fromJSON
    (builtins.readFile ../../tests/abilities/fixtures/invalid-configuration-schema.json);
  invalidConfigurationExport = builtins.tryEval (builtins.deepSeq (
      (configurationExport invalidConfigurationSchema).configuration_schema
    )
    true);

  requirementExport = strength: fallback:
    lib.abilities.define {
      interface = "aos.test.requirement";
      abi = 1;
      requestSchema = lib.abilities.schemas.boolean;
      outputs = {};
      methods = {};
      lifecycle = {
        stableResourceIdentity = true;
        releasesEphemeralOnDisable = true;
        retainsPersistentByDefault = true;
        persistentDeleteMethod = null;
      };
      guarantees = [];
      aggregation = {
        scope = "provider-instance";
        key = "authorized-slot";
        rejectSlotCollisions = true;
        mergeContract = null;
        controllerGroup = "requirement";
      };
      requires.optional = {
        interface = testInterface.name;
        abi = testInterface.abi;
        descriptor = testInterface.descriptor;
        methods = [];
        guarantees = [];
        inherit strength fallback;
      };
      ownsResourceKinds = [];
      handler = "requirement-handler";
    };
  advisoryRequirement =
    (requirementExport "advisory" {
      outputs = {
        enabled = true;
        endpoint = null;
      };
    }).requirements.optional;
  requiredFallback = builtins.tryEval (builtins.deepSeq (
      requirementExport "required" {outputs.enabled = true;}
    )
    true);
  advisoryWithoutFallback = builtins.tryEval (builtins.deepSeq (
      requirementExport "advisory" null
    )
    true);
  nonCanonicalFallback = builtins.tryEval (builtins.deepSeq (
      requirementExport "advisory" {outputs.enabled = 1.5;}
    )
    true);

  composition = import ../../tests/abilities/composition.nix {
    inherit (lib) abilities;
  };
  expansion = composition.expansion;
  nodeIn = value: name:
    builtins.head (builtins.filter (entry: entry.registry_key == name) value.nodes);
  node = nodeIn expansion;
  collision = builtins.tryEval (builtins.deepSeq composition.collision true);
  duplicateProviderAlias = builtins.tryEval (builtins.deepSeq composition.duplicateProviderAlias true);
  providerCycle = builtins.tryEval (builtins.deepSeq composition.providerCycle true);
  badResult = builtins.tryEval (builtins.deepSeq composition.badResult true);
  lateResult = builtins.tryEval (builtins.deepSeq composition.lateResult true);
  exportDeclaration =
    lib.abilities.normalizeExportDeclaration
    "configuration"
    "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
    composition.configurationExport;
  emptyEffects = lib.abilities.effects.normalize [] (
    lib.abilities.effects.when false (lib.abilities.effects.graph {})
  );
  effectFixture = import ../../tests/abilities/effects.nix {
    inherit (lib) abilities;
  };
  effectPlan = effectFixture.normalized;
  postgresqlReconciliation = import ../../tests/abilities/reference-postgresql/reconciliation.nix;
  productionKubernetes = import ../../tests/abilities/production-kubernetes.nix {
    inherit pkgs lib;
  };
  acceptedEffectImageFamily =
    (builtins.head
      (effectFixture.familyPlan {
        kind = "image-rollout";
        action = "retain";
      }).operations)
    .family;
  invalidEffectImageFamily = builtins.tryEval (builtins.deepSeq (
      effectFixture.familyPlan {
        kind = "image-rollout";
        action = "unknown";
      }
    )
    true);
  oversizedFallback = builtins.tryEval (builtins.deepSeq (
      requirementExport "advisory" {outputs.payload = effectFixture.oversizedValue;}
    )
    true);
  unsupportedEffects = builtins.tryEval (builtins.deepSeq (
      lib.abilities.effects.normalize [] (
        lib.abilities.effects.graph {operation = {};}
      )
    )
    true);
  forgedEffects = {
    _type = "aos-effect-graph";
    operations = {};
    decisions = {hidden = {};};
  };
  reservedAbilityOutputRejected = output:
    !(builtins.tryEval ((pkgs.mkDerivation {
        pname = "ability-output-collision";
        version = "0";
        src = null;
        outputs = ["out" output];
        phases = [];
        abilityPackage = {};
      })
      .abilities
      .outPath))
    .success;
  proseVariant = prose:
    pkgs.mkDerivation {
      pname = "ability-prose-invariance";
      version = "1.0.0";
      src = ../../tests/abilities/prose-invariance;
      phases = [
        {
          name = "install";
          script = ''
            mkdir -p "$out/share/ability-prose-invariance"
            echo payload > "$out/share/ability-prose-invariance/value"
          '';
        }
      ];
      configModule = {
        src = ../../tests/abilities/prose-invariance;
        moduleAbiCompat = {
          min = 1;
          max = 1;
        };
        declares = [];
        documentation.sections.reference = lib.aosDoc.section "Reference" [
          (lib.aosDoc.paragraph prose)
        ];
      };
      abilityPackage = {};
    };
  proseBefore = proseVariant "Original package guidance.";
  proseAfter = proseVariant "Revised package guidance with no contract change.";
  authoringConformance = import ./ability-authoring-conformance.nix {
    inherit pkgs lib;
  };
in
  assert reservedAbilityOutputRejected "abilities";
  assert reservedAbilityOutputRejected "abilityPackage";
  # Documentation prose is retained in the config companion and therefore
  # changes that companion (and the later documentation object's identity).
  # mkDerivation removes configModule before building the payload and prepares
  # the ability companion only from payload/source/ability declarations, so the
  # exact package manifest, semantic package digest, and transition inputs stay
  # byte-identical across this prose-only edit.
  assert proseBefore.config.drvPath != proseAfter.config.drvPath;
  assert proseBefore.drvPath == proseAfter.drvPath;
  assert proseBefore.abilities.drvPath == proseAfter.abilities.drvPath;
  assert canonicalInterface == expectedInterface;
  assert interfaceDocument.schema == "aos.ability.interface/v1";
  assert interfaceDocument.interface.name == "aos.test.echo";
  assert interfaceDocument.interface.methods.observe.outputs.ready.phase == "observation";
  assert validOptionalRecord == {enabled = true;};
  assert lib.abilities.schemas.enum [""]
  == {
    kind = "string-enum";
    values = [""];
  };
  assert builtins.attrValues asciiControlMap == [true];
  assert (configurationExport literalConfigurationSchema).configuration_schema
  == literalConfigurationSchema;
  assert !invalidConfigurationExport.success;
  assert fails (lib.abilities.schemas.checkValue (lib.abilities.schemas.map {
      keyMaxLength = 16;
      keySyntax = null;
      maxEntries = 1;
      value = lib.abilities.schemas.boolean;
    })
    nonAsciiMap);
  assert fails (lib.abilities.schemas.integer {
    minimum = -9007199254740992;
    maximum = 0;
  });
  assert fails (lib.abilities.schemas.validateSchema "raw integer" {
    kind = "integer";
    minimum = 0;
    maximum = 9007199254740992;
  });
  assert fails (lib.abilities.schemas.string {
    maxLength = 1048577;
    syntax = null;
  });
  assert fails (lib.abilities.schemas.validateSchema "raw string" {
    kind = "string";
    max_length = 1048577;
    syntax = null;
  });
  assert fails (lib.abilities.schemas.list {
    element = lib.abilities.schemas.boolean;
    maxItems = 2000001;
  });
  assert fails (lib.abilities.schemas.validateSchema "raw map" {
    kind = "map";
    key = {
      max_length = 16;
      syntax = null;
    };
    max_entries = 2000001;
    value = {kind = "boolean";};
  });
  assert lib.abilities.schemas.validateSchema "at-limit schema" atLimitSchema == atLimitSchema;
  assert fails (lib.abilities.schemas.validateSchema "over-limit schema" overLimitSchema);
  assert lib.abilities.schemas.validateSchema "provider assignment" lib.abilities.schemas.providerAssignment
  == {kind = "provider-assignment";};
  assert fails (lib.abilities.schemas.validateSchema "provider assignment" {
    kind = "provider-assignment";
    unexpected = true;
  });
  assert fails (lib.abilities.schemas.checkValue lib.abilities.schemas.resourceReference {
    _type = "aos-resource-reference";
    interface = {
      name = "aos.test.invalid";
      abi = 4294967296;
      descriptor = "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
    };
    resource = {
      provider = {
        environment = {
          authority = "deployment";
          key = "test";
          stage = "host";
        };
        key = "provider";
      };
      key = "resource";
    };
    operations = [];
    lifetime = "instance";
  });
  assert fails (lib.abilities.schemas.checkValue lib.abilities.schemas.operationResultReference {
    _type = "aos-operation-result-reference";
    operation.key = "old-unscoped";
    output = "value";
  });
  assert fails (lib.abilities.environmentId {
    authority = "deployment";
    key = "test";
    stage = "invalid";
  });
  assert fails (lib.abilities.requestId {
    consumer = testInstanceId;
    scope = builtins.genList (_: "nested") 65;
    key = "request";
  });
  assert fails (lib.abilities.resourceReference {
    interface = testInterface;
    resource = {
      provider = testInstanceId;
      key = "resource";
    };
    operations = ["invalid operation"];
    lifetime = "instance";
  });
  assert fails (lib.abilities.resourceReference {
    interface = testInterface;
    resource = {
      provider = testInstanceId;
      key = "resource";
    };
    operations = [];
    lifetime = "forever";
  });
  assert fails (lib.abilities.artifactReference {
    content = "sha256:1111111111111111111111111111111111111111111111111111111111111111";
    storePath = 42;
    narHash = "sha256:2222222222222222222222222222222222222222222222222222222222222222";
    closure = "sha256:3333333333333333333333333333333333333333333333333333333333333333";
  });
  assert guaranteeOrdering == ["aos.a:2" "aos.a:10" "aos.a.long:1" "aos.zz:1"];
  assert acceptedMethodImageFamily
  == {
    kind = "image-rollout";
    action = "retain";
  };
  assert acceptedEffectImageFamily == acceptedMethodImageFamily;
  assert !invalidMethodImageFamily.success;
  assert !invalidEffectImageFamily.success;
  assert advisoryRequirement.strength == "advisory";
  assert advisoryRequirement.fallback.outputs
  == {
    enabled = true;
    endpoint = null;
  };
  assert !requiredFallback.success;
  assert !advisoryWithoutFallback.success;
  assert !nonCanonicalFallback.success;
  assert !oversizedFallback.success;
  assert !invalidNestedSchema.success;
  assert expansion == composition.reversed;
  assert expansion.round == 3;
  assert builtins.map (entry: entry.registry_key) expansion.nodes == ["managed" "nginx-edge" "nginx-internal" "systemd"];
  assert (node "nginx-edge").outputs.count == 2;
  assert (node "nginx-internal").outputs.count == 1;
  assert builtins.map (entry: entry.slot) (node "managed").contributions
  == [
    "nginx-edge.configuration"
    "nginx-edge.metadata"
    "nginx-internal.configuration"
    "nginx-internal.metadata"
  ];
  assert builtins.map (entry: entry.request.scope) (node "managed").contributions
  == [
    ["nginx-edge" "configuration"]
    ["nginx-edge" "metadata"]
    ["nginx-internal" "configuration"]
    ["nginx-internal" "metadata"]
  ];
  assert builtins.map (entry: entry.grant) (node "managed").contributions
  == [
    "nginx-edge.configuration"
    "nginx-edge.metadata"
    "nginx-internal.configuration"
    "nginx-internal.metadata"
  ];
  assert builtins.length (node "systemd").contributions == 2;
  assert (builtins.head (node "systemd").contributions).value.configuration._type == "aos-resource-reference";
  assert (nodeIn composition.emptyRoot "nginx-edge").contributions == [];
  assert (nodeIn composition.emptyRoot "nginx-edge").outputs.count == 0;
  assert (nodeIn composition.tlsOff "nginx-edge").conditional_requirements == [];
  assert !(builtins.elem "credentials" (builtins.map (entry: entry.registry_key) composition.tlsOff.nodes));
  assert (nodeIn composition.tlsOn "nginx-edge").conditional_requirements == ["credential"];
  assert builtins.length (nodeIn composition.tlsOn "credentials").contributions == 1;
  assert !collision.success;
  assert !duplicateProviderAlias.success;
  assert !providerCycle.success;
  assert !badResult.success;
  assert !lateResult.success;
  assert exportDeclaration
  == {
    name = "configuration";
    interface = {
      name = "aos.managed-configuration";
      abi = 1;
      descriptor = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    };
    aggregation = {
      scope = "provider-instance";
      key = "authorized-slot";
      controller_group = "configuration";
      reject_slot_collisions = true;
      merge_contract = null;
    };
    implementation = "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";
  };
  assert emptyEffects
  == {
    artifacts = [];
    operations = [];
    decisions = [];
    merges = [];
    edges = [];
    provider_readiness = [];
  };
  assert !unsupportedEffects.success;
  assert fails (lib.abilities.effects.normalize [] forgedEffects);
  assert effectPlan == effectFixture.reversed;
  assert builtins.length effectPlan.artifacts == 1;
  assert builtins.length effectPlan.operations == 11;
  assert builtins.length effectPlan.decisions == 6;
  assert builtins.length effectPlan.merges == 2;
  assert builtins.length effectPlan.edges == 29;
  assert builtins.length effectFixture.longChain.operations == 65;
  assert builtins.length effectFixture.longChain.edges == 64;
  assert builtins.map (operation: operation.key) effectPlan.operations
  == [
    {
      scope = ["nginx"];
      key = "candidate";
    }
    {
      scope = ["nginx"];
      key = "change";
    }
    {
      scope = ["nginx"];
      key = "final";
    }
    {
      scope = ["nginx"];
      key = "mode";
    }
    {
      scope = ["nginx"];
      key = "policy";
    }
    {
      scope = ["nginx"];
      key = "publish";
    }
    {
      scope = ["nginx"];
      key = "record";
    }
    {
      scope = ["nginx" "choice" "false"];
      key = "apply";
    }
    {
      scope = ["nginx" "choice" "true"];
      key = "apply";
    }
    {
      scope = ["nginx" "modeChoice" "reload"];
      key = "apply";
    }
    {
      scope = ["nginx" "modeChoice" "restart"];
      key = "apply";
    }
  ];
  assert (builtins.head effectPlan.merges).outputs.ready.descriptor.schema == lib.abilities.schemas.boolean;
  assert builtins.elem "branch-guard" (builtins.map (edge: edge.kind) effectPlan.edges);
  assert builtins.elem "branch-merge" (builtins.map (edge: edge.kind) effectPlan.edges);
  assert effectFixture.bootstrap.provider_readiness
  == [
    {
      binding = "nginx.configuration";
      producer = {
        scope = ["bootstrap"];
        key = "bootstrap";
      };
      output = "assignment";
    }
  ];
  assert builtins.elem {
    from = {
      kind = "operation";
      key = {
        scope = ["bootstrap"];
        key = "bootstrap";
      };
    };
    to = {
      kind = "operation";
      key = {
        scope = ["bootstrap"];
        key = "consumer";
      };
    };
    kind = "readiness";
  }
  effectFixture.bootstrap.edges;
  assert (builtins.head effectFixture.kubernetes.operations).family
  == {
    kind = "kubernetes-object";
    action = "apply";
  };
  assert effectFixture.omitted == emptyEffects;
  assert postgresqlReconciliation.reconcile_stopped == ["materialize" "observe" "start" "stop"];
  assert postgresqlReconciliation.reconcile_divergent == ["materialize" "observe" "restart" "stop"];
  assert productionKubernetes;
  assert fails (lib.abilities.effects.normalize [] effectFixture.missingReference);
  assert fails (lib.abilities.effects.normalize [] effectFixture.cycle);
  assert fails (lib.abilities.effects.normalize [] effectFixture.incompleteBoolean);
  assert fails (lib.abilities.effects.normalize ["nginx"] effectFixture.escapingReference);
  assert fails (lib.abilities.effects.normalize ["nginx"] effectFixture.externalMergeProducer);
  assert fails (lib.abilities.effects.normalize ["bootstrap"] effectFixture.duplicateProviderReadiness);
  assert fails (lib.abilities.effects.normalize ["bootstrap"] effectFixture.mergedProviderReadiness);
  assert fails (lib.abilities.effects.normalize ["bootstrap"] effectFixture.escapingProviderReadiness);
  assert fails (lib.abilities.effects.normalize ["bootstrap"] effectFixture.missingReadinessProducer);
  assert fails (lib.abilities.effects.normalize ["bootstrap"] effectFixture.unusedProviderReadiness);
  assert fails (lib.abilities.effects.normalize ["bootstrap"] effectFixture.oversizedProviderReadiness);
  assert fails (lib.abilities.effects.normalize ["chain"] effectFixture.analysisHeavyChain);
  assert fails (lib.abilities.effects.normalize ["nginx"] effectFixture.oversizedDocument);
    pkgs.mkDerivation {
      pname = "aos-ability-authoring-checks";
      version = "0";
      src = null;
      phases = [
        {
          name = "check";
          script = ''
            mkdir -p "$out"
            echo PASS > "$out/result"
          '';
        }
      ];
      buildDeps = [authoringConformance];
    }
