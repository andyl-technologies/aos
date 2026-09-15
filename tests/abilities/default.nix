##! tests/abilities/default.nix - Pure ability authoring and wire fixtures.
{
  pkgs,
  lib,
  mkSystem,
}: let
  fails = value: !(builtins.tryEval (builtins.deepSeq value true)).success;
  boundedSelectorNormalizer = import ../../lib/abilities/package-output-selectors.nix {
    diagnostics = import ../../lib/abilities/diagnostic.nix;
    limits = {
      maxCollectionItems = 4;
      maxStringBytes = 16;
      maxStructuralDepth = 4;
    };
  };
  normalizeBounded = value:
    boundedSelectorNormalizer.normalizePackageOutputSelectors {
      owner = "test";
      inherit value;
    };

  interfaceDocument = import ./interface.nix {
    inherit (lib) abilities;
  };
  canonicalInterface = builtins.toJSON interfaceDocument;
  expectedInterface = builtins.readFile ./fixtures/interface.json;

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

  canonicalListType = lib.abilities.types.list {
    element = lib.abilities.types.string {
      maxLength = 16;
      syntax = null;
    };
    maxItems = 4;
    unique = true;
    canonicalOrder = true;
  };
  canonicalListSchema = lib.abilities.types.schemaOf "canonical list test" canonicalListType;
  mergedCanonicalList = canonicalListType.merge ["test" "methods"] [
    {
      file = "first";
      value = ["beta" "alpha"];
    }
    {
      file = "second";
      value = ["beta"];
    }
  ];

  scalarUnionType = lib.abilities.types.disjointUnion [
    (lib.abilities.types.string {
      maxLength = 16;
      syntax = null;
    })
    lib.abilities.types.boolean
    (lib.abilities.types.integer {
      minimum = 0;
      maximum = 16;
    })
  ];
  scalarUnionSchema = lib.abilities.types.schemaOf "scalar union test" scalarUnionType;
  ambiguousUnion = builtins.tryEval (builtins.deepSeq (
      lib.abilities.types.schemaOf "ambiguous union test" (lib.abilities.types.disjointUnion [
        (lib.abilities.types.string {
          maxLength = 16;
          syntax = null;
        })
        (lib.abilities.types.enum ["same-kind"])
      ])
    )
    true);

  documentRecordType = lib.abilities.types.documentRecord {
    keyMaxLength = 32;
    fields = {
      "@type" = lib.abilities.types.string {
        maxLength = 64;
        syntax = null;
      };
      enabled = lib.abilities.types.boolean;
    };
    optional = ["enabled"];
  };
  documentRecordSchema = lib.abilities.types.schemaOf "document record test" documentRecordType;

  deferredExecutionPath = lib.abilities.types.deferredResult lib.abilities.types.executionPath;
  qualifiedDeferredExecutionPath = {
    _type = "aos-request-output-reference";
    request = "system:runtime-directory";
    output = "execution-path";
  };
  pathWithin = lib.abilities.pathWithin {
    base = lib.abilities.resultOf "runtime-directory" "execution-path";
    relativePath = "krb5/service.pid";
  };
  invalidPathWithin = builtins.tryEval (builtins.deepSeq (lib.abilities.pathWithin {
      base = "/run/krb5";
      relativePath = "../service.pid";
    })
    true);
  nonPathDeferred = lib.abilities.types.deferredResult (lib.abilities.types.integer {
    minimum = 0;
    maximum = 16;
  });
  forgedIntegerPathWithin = {
    _type = "aos-runtime-path";
    base = 1;
    relative_path = "child";
  };

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
      requestSchema = lib.abilities.types.boolean;
      outputs = {};
      methods = {};
      lifecycle = {
        stableResourceIdentity = true;
        releasesEphemeralOnDisable = false;
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
    })
    .guarantees;

  methodSemantics = name: {
    requiredTargetAccess =
      if builtins.elem name ["observe" "observe-boot" "observe-health" "validate" "verify"]
      then "read"
      else "exclusive-write";
    stopsProvider = name == "stop";
  };
  methodSemanticsInterfaceFor = releasesEphemeralOnDisable: semantics:
    lib.abilities.define {
      interface = "aos.test.method-family";
      abi = 1;
      requestSchema = lib.abilities.types.boolean;
      outputs = {};
      methods.run = {
        inherit semantics;
        parameters = lib.abilities.types.boolean;
        targetResource = "aos.test.method-family";
        outputs = {};
        permittedOperations = ["run"];
        guarantees = [];
        outcome = {
          completionEvidence = lib.abilities.types.boolean;
          observationEvidence = lib.abilities.types.boolean;
          supportsRejectedBeforeEffect = true;
          indeterminate = "reconcile";
        };
      };
      lifecycle = {
        stableResourceIdentity = true;
        inherit releasesEphemeralOnDisable;
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
  methodSemanticsInterface = methodSemanticsInterfaceFor false;
  acceptedMethodSemantics =
    (methodSemanticsInterface {
      requiredTargetAccess = "exclusive-write";
      stopsProvider = false;
    })
    .methods
    .run
    .semantics;
  invalidMethodSemantics = builtins.tryEval (builtins.deepSeq (
      (methodSemanticsInterface {
        requiredTargetAccess = "invalid";
        stopsProvider = false;
      })
      .methods
      .run
      .semantics
    )
    true);
  invalidReleasePromise = builtins.tryEval (builtins.deepSeq (
      methodSemanticsInterfaceFor true {
        requiredTargetAccess = "exclusive-write";
        stopsProvider = false;
      }
    )
    true);

  configurationExport = configurationSchema:
    lib.abilities.define {
      interface = "aos.test.configuration";
      abi = 1;
      requestSchema = lib.abilities.types.boolean;
      inherit configurationSchema;
      outputs = {};
      methods = {};
      lifecycle = {
        stableResourceIdentity = true;
        releasesEphemeralOnDisable = false;
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
  literalConfigurationType = lib.abilities.types.record {
    fields.ports = lib.abilities.types.list {
      element = lib.abilities.types.integer {
        minimum = 1024;
        maximum = 65535;
      };
      maxItems = 8;
    };
    optional = [];
  };
  invalidConfigurationSchema =
    builtins.fromJSON
    (builtins.readFile ./fixtures/invalid-configuration-schema.json);
  invalidConfigurationExport = builtins.tryEval (builtins.deepSeq (
      (configurationExport invalidConfigurationSchema).configuration_schema
    )
    true);

  requirementExport = strength: fallback:
    lib.abilities.define {
      interface = "aos.test.requirement";
      abi = 1;
      requestSchema = lib.abilities.types.boolean;
      outputs = {};
      methods = {};
      lifecycle = {
        stableResourceIdentity = true;
        releasesEphemeralOnDisable = false;
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
    })
    .requirements
    .optional;
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

  composition = import ./composition.nix {
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
  effectFixture = import ./effects.nix {
    inherit (lib) abilities;
  };
  effectPlan = effectFixture.normalized;
  kubernetesPackageServices = import ./kubernetes-package-services.nix {
    inherit lib pkgs;
  };
  attestationVerifierService = import ./attestation-verifier-service.nix {
    inherit lib pkgs;
  };
  kubernetesObjectManagementCore = import ./kubernetes-object-management-core.nix {
    inherit lib;
  };
  serviceManagement = import ./service-management.nix {
    inherit lib;
  };
  managedIdentityAllocation = import ./managed-identity-allocation.nix {
    inherit lib;
  };
  systemServiceModules = import ./system-service-modules.nix {
    inherit lib;
  };
  dockerService = import ./docker-service.nix {
    inherit pkgs lib;
  };
  containerdStaticProjection = import ./containerd-static-projection.nix {
    inherit pkgs lib;
  };
  kernelModules = import ./kernel-modules.nix {
    inherit lib;
  };
  bootPreparationCore = import ./boot-preparation-core.nix {
    inherit lib;
  };
  nixStoreDatabase = import ./nix-store-database.nix {
    inherit lib;
  };
  postgresqlService = import ./postgresql-service.nix {
    inherit lib pkgs;
  };
  releaseCoordinatorService = import ./release-coordinator-service.nix {
    inherit lib;
  };
  networkPolicyCore = import ./network-policy-core.nix {
    inherit lib;
  };
  securityWrappers = import ./security-wrappers.nix {
    inherit lib;
  };
  kernelTunables = import ./kernel-tunables.nix {
    inherit lib;
  };
  filesystemEntryProvider = import ./filesystem-entry-provider.nix {
    inherit lib pkgs;
  };
  zram = import ./zram.nix {
    inherit lib pkgs;
  };
  packageQualification = import ./package-qualification.nix {
    inherit lib pkgs;
  };
  compositionDriver = import ./composition-driver.nix {
    inherit lib;
  };
  systemdPackagedUnit = import ./systemd-packaged-unit.nix {
    inherit pkgs lib;
  };
  systemdServiceRealization = import ./systemd-service-realization.nix {
    inherit pkgs lib;
  };
  systemdDirectoryPreparation = import ./systemd-directory-preparation.nix {
    inherit pkgs lib;
  };
  systemdReadiness = import ./systemd-readiness.nix {
    inherit pkgs lib;
  };
  baseKernelNative = import ./base-kernel-native.nix {
    inherit pkgs lib;
  };
  baseNixDbNative = import ./base-nix-db-native.nix {
    inherit pkgs lib;
  };
  baseNetworkingNative = import ./base-networking-native.nix {
    inherit pkgs lib;
  };
  baseHardeningNative = import ./base-hardening-native.nix {
    inherit pkgs lib;
  };
  smokeAbilityProjection = pkgs.ability-package-smoke.abilities;
  smokeArtifactSelectors = pkgs.ability-package-smoke.contract.selectors;
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
        abilities = ../build/fixtures/ability-module-file.nix;
      })
      .abilities))
    .success;
  inlineAbilitiesRejected =
    !(
      builtins.tryEval (pkgs.mkDerivation {
        pname = "inline-ability-module";
        version = "0";
        src = null;
        phases = [];
        abilities = {config.aos.abilities = {};};
      })
    )
    .success;
  authoringConformance = import ./authoring-conformance.nix {
    inherit pkgs lib;
  };
  disabledRsyncProjection = pkgs.rsync.abilities;
  selectedChronySystem = mkSystem {
    modules = [
      {
        aos.abilities.environment = {
          authority = "test";
          key = "selected-chrony";
          stage = "host";
        };
        aos.services.chrony.enable = true;
      }
    ];
    systemName = "selected-chrony";
  };
  selectedChronyAbilities = selectedChronySystem.config.aos.abilities;
in
  assert canonicalListType.check ["alpha" "beta"];
  assert canonicalListSchema.unique && canonicalListSchema.canonical_order;
  assert canonicalListType._aosDocType.unique && canonicalListType._aosDocType.canonical_order;
  assert mergedCanonicalList == ["alpha" "beta"];
  assert !canonicalListType.check ["alpha" "alpha"];
  assert !canonicalListType.check ["beta" "alpha"];
  assert scalarUnionType.check true;
  assert scalarUnionType.check 4;
  assert scalarUnionType.check "raw";
  assert !scalarUnionType.check [];
  assert builtins.map (variant: variant.kind) scalarUnionSchema.variants == ["boolean" "integer" "string"];
  assert !ambiguousUnion.success;
  assert lib.abilities.schemas.checkValue documentRecordSchema {"@type" = "type.googleapis.com/example";}
  == {"@type" = "type.googleapis.com/example";};
  assert builtins.attrNames documentRecordType._aosDocType.fields == ["@type" "enabled"];
  assert documentRecordType._aosDocType.kind == "document-record";
  assert documentRecordType._aosDocType.key_max_length == 32;
  assert scalarUnionType._aosDocType.kind == "disjoint-union";
  assert deferredExecutionPath.check pathWithin;
  assert deferredExecutionPath.check qualifiedDeferredExecutionPath;
  assert !deferredExecutionPath.check (qualifiedDeferredExecutionPath // {request = "nested:invalid:key";});
  assert pathWithin._type == "aos-runtime-path";
  assert pathWithin.relative_path == "krb5/service.pid";
  assert !invalidPathWithin.success;
  assert !nonPathDeferred.check forgedIntegerPathWithin;
  assert (lib.abilities.types.schemaOf "execution path" lib.abilities.types.executionPath).syntax == "execution-path-v1";
  assert fails (lib.abilities.schemas.checkValue documentRecordSchema {unknown = true;});
  assert reservedAbilityOutputRejected "abilities";
  assert reservedAbilityOutputRejected "abilityContract";
  assert reservedAbilityOutputRejected "abilityModule";
  assert reservedAbilityOutputRejected "module";
  assert inlineAbilitiesRejected;
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
  assert (configurationExport literalConfigurationType).configuration_schema
  == lib.abilities.types.schemaOf "literal configuration" literalConfigurationType;
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
  assert acceptedMethodSemantics
  == {
    required_target_access = "exclusive-write";
    stops_provider = false;
  };
  assert !invalidMethodSemantics.success;
  assert !invalidReleasePromise.success;
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
  assert let
    consumer = builtins.head (builtins.filter (operation: operation.key.key == "consumer") effectFixture.pathWithin.operations);
  in
    consumer.inputs.fields.pid_file
    == {
      source = "path-within";
      base = {
        source = "operation-result";
        reference = {
          producer = {
            kind = "operation";
            key = {
              scope = ["path-within"];
              key = "directory";
            };
          };
          output = "execution-path";
        };
      };
      relative_path = "krb5/service.pid";
    };
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
  assert !(builtins.head effectFixture.kubernetes.operations ? semantics);
  assert effectFixture.omitted == emptyEffects;
  assert kubernetesPackageServices;
  assert attestationVerifierService;
  assert kubernetesObjectManagementCore;
  assert serviceManagement;
  assert managedIdentityAllocation;
  assert systemServiceModules;
  assert compositionDriver;
  assert systemdPackagedUnit;
  assert systemdServiceRealization;
  assert systemdDirectoryPreparation;
  assert systemdReadiness;
  assert baseKernelNative;
  assert baseNixDbNative;
  assert baseNetworkingNative;
  assert baseHardeningNative;
  assert builtins.attrNames smokeAbilityProjection.implementations == ["default"];
  assert builtins.attrNames smokeAbilityProjection.interfaces == ["default"];
  assert builtins.length (builtins.attrNames smokeAbilityProjection.requirementTemplates) == 1;
  assert smokeArtifactSelectors
  == [
    {
      package = "ability-package-smoke";
      output = "out";
    }
    {
      package = "ability-package-smoke-provider";
      output = "out";
    }
    {
      package = "self";
      output = "module";
    }
  ];
  assert builtins.length (builtins.attrNames disabledRsyncProjection.requirementTemplates) > 0;
  assert selectedChronyAbilities.instances ? "chrony:service";
  assert selectedChronyAbilities.requests ? "chrony:chronyd-lifecycle";
  assert selectedChronyAbilities.requests ? "chrony:chrony-configuration";
  assert dockerService;
  assert containerdStaticProjection;
  assert zram;
  assert kernelModules;
  assert bootPreparationCore;
  assert nixStoreDatabase;
  assert postgresqlService;
  assert securityWrappers;
  assert releaseCoordinatorService;
  assert filesystemEntryProvider;
  assert networkPolicyCore;
  assert kernelTunables;
  assert packageQualification;
  assert fails (normalizeBounded [true false null true false]);
  assert fails (normalizeBounded {oversized-member-name = true;});
  assert fails (normalizeBounded "0123456789abcdefg");
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
