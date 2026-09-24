##! tests/abilities/default.nix - Pure ability authoring and wire fixtures.
{
  pkgs,
  lib,
  mkSystem,
}: let
  fails = value: !(builtins.tryEval (builtins.deepSeq value true)).success;
  boundedSelectorNormalizer = lib.abilities.packageOutputSelectorsFor {
    maxCollectionItems = 4;
    maxStringBytes = 16;
    maxStructuralDepth = 4;
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
  packageStoreReadViewDocument =
    lib.abilities.interfaceDocumentFromDeclaration
    lib.abilities.interfaces.packageStoreReadView.interfaces.readView.declaration;
  canonicalPackageStoreReadView = builtins.toJSON packageStoreReadViewDocument;
  expectedPackageStoreReadView = builtins.readFile ../../crates/aos-package-store-model/tests/fixtures/package-store-read-view-interface.json;

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
  canonicalJsonSourceType = lib.abilities.types.record {
    fields.enabled = lib.abilities.types.boolean;
  };
  canonicalJson = lib.abilities.canonicalJsonOf {
    type = canonicalJsonSourceType;
    value = lib.abilities.resultOf "selected-record" "locator";
    maxBytes = 128;
  };
  deferredRuntimeString = lib.abilities.types.deferredResult lib.abilities.types.runtimeString;
  canonicalJsonNixEncoding = builtins.toJSON {
    z = false;
    a = true;
  };
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
  descriptorAgnosticSelector = {
    inherit (testInterface) name abi;
    descriptor = null;
  };
  mismatchedDescriptorSelector =
    descriptorAgnosticSelector
    // {
      descriptor = "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";
    };

  kubernetesPackageServices = import ./kubernetes-package-services.nix {
    inherit lib pkgs;
  };
  upgradeTransitionFixture = import ./upgrade-transition-fixture.nix {
    inherit lib pkgs;
  };
  k3sControllerTerminal = import ./k3s-controller-terminal.nix {
    inherit lib pkgs;
  };
  attestationVerifierService = import ./attestation-verifier-service.nix {
    inherit lib pkgs;
  };
  aosPackageRuntimeServices = import ./aos-package-runtime-services.nix {
    inherit lib pkgs;
  };
  configurationEvaluationService = import ./configuration-evaluation-service.nix {
    inherit lib pkgs;
  };
  abilityCrucibleService = import ./ability-crucible-service.nix {
    inherit lib pkgs;
  };
  abilityBoundaryObserverService = import ./ability-boundary-observer-service.nix {
    inherit lib pkgs;
  };
  zfstoolsService = import ./zfstools-service.nix {
    inherit lib pkgs;
  };
  libvirtService = import ./libvirt-service.nix {
    inherit lib pkgs;
  };
  nginxService = import ./nginx-service.nix {
    inherit lib pkgs;
  };
  mariadbService = import ./mariadb-service.nix {
    inherit lib pkgs;
  };
  krb5KdcService = import ./krb5-kdc-service.nix {
    inherit lib pkgs;
  };
  serviceManagement = import ./service-management.nix {
    inherit lib;
  };
  dbusService = import ./dbus-service.nix {
    inherit lib;
  };
  dbusRegistrationTransition = import ./dbus-registration-transition.nix {
    inherit lib;
  };
  bindService = import ./bind-service.nix {
    inherit lib;
  };
  smartmontoolsService = import ./smartmontools-service.nix {
    inherit lib;
  };
  serviceFeatures = import ./service-features.nix {
    inherit lib pkgs;
  };
  managedIdentityAllocation = import ./managed-identity-allocation.nix {
    inherit lib pkgs;
  };
  dockerService = import ./docker-service.nix {
    inherit pkgs lib;
  };
  tailscaleService = import ./tailscale-service.nix {
    inherit pkgs lib;
  };
  packageOptionProvenance = import ./package-option-provenance.nix {
    inherit pkgs;
  };
  nftablesFirewall = import ./nftables-firewall.nix {
    inherit pkgs lib;
  };
  containerdStaticProjection = import ./containerd-static-projection.nix {
    inherit pkgs lib;
  };
  kernelModules = import ./kernel-modules.nix {
    inherit lib pkgs;
  };
  bootPreparationCore = import ./boot-preparation-core.nix {
    inherit lib;
  };
  nixStoreDatabase = import ./nix-store-database.nix {
    inherit lib pkgs;
  };
  bootPreparationProvider = import ./boot-preparation-provider.nix {
    inherit lib pkgs;
  };
  bootStorageServices = import ./boot-storage-services.nix {
    inherit lib pkgs;
  };
  stagedEnvironment = import ./staged-environment.nix {
    inherit lib pkgs mkSystem;
  };
  postgresqlService = import ./postgresql-service.nix {
    inherit lib pkgs;
  };
  releaseCoordinatorService = import ./release-coordinator-service.nix {
    inherit lib pkgs;
  };
  networkPolicyCore = import ./network-policy-core.nix {
    inherit lib;
  };
  selectedPackageProviderDiscovery = import ./selected-package-provider-discovery.nix {
    inherit lib pkgs;
  };
  securityWrappers = import ./security-wrappers.nix {
    inherit lib pkgs;
  };
  kernelTunables = import ./kernel-tunables.nix {
    inherit lib pkgs;
  };
  blockStorage = import ./block-storage.nix {
    inherit lib pkgs;
  };
  baseFilesystemsNative = import ./base-filesystems-native.nix {
    inherit lib pkgs;
  };
  filesystemEntryProvider = import ./filesystem-entry-provider.nix {
    inherit lib pkgs;
  };
  aosControllerTerminal = import ./aos-controller-terminal.nix {
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
  systemdQualificationChecks = import ./systemd-qualification-checks.nix {
    inherit lib;
  };
  utilLinuxGetty = import ./util-linux-getty.nix {
    inherit pkgs lib mkSystem;
  };
  systemdIdentityRealization = import ./systemd-identity-realization.nix {
    inherit pkgs lib;
  };
  systemdNativeResources = import ./systemd-native-resources.nix {
    inherit pkgs lib;
  };
  aosControlPlane = import ./aos-control-plane.nix {
    inherit pkgs lib;
  };
  systemdReadiness = import ./systemd-readiness.nix {
    inherit pkgs lib;
  };
  systemdStageMilestones = import ./systemd-stage-milestones.nix {
    inherit pkgs lib;
  };
  initrdSecurityServices = import ./initrd-security-services.nix {
    inherit pkgs lib mkSystem;
  };
  initrdBootSubstrate = import ./initrd-boot-substrate.nix {
    inherit pkgs lib;
  };
  packageStoreReadView = import ./package-store-read-view.nix {
    inherit pkgs lib;
  };
  artifactBackend = import ./artifact-backend.nix {
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
  eventLogPolicy = import ./event-log-policy.nix {
    inherit pkgs lib;
  };
  loginSessionTracking = import ./login-session-tracking.nix {
    inherit pkgs lib;
  };
  baseHardeningNative = import ./base-hardening-native.nix {
    inherit pkgs lib;
  };
  securityAuditNative = import ./security-audit-native.nix {
    inherit pkgs lib;
  };
  securityEbpfLsmNative = import ./security-ebpf-lsm-native.nix {
    inherit pkgs lib;
  };
  securityEbpfNetworkNative = import ./security-ebpf-network-native.nix {
    inherit pkgs lib;
  };
  securityPolkitNative = import ./security-polkit-native.nix {
    inherit pkgs lib;
  };
  securitySelinuxNative = import ./security-selinux-native.nix {
    inherit pkgs lib;
  };
  securitySshNative = import ./security-ssh-native.nix {
    inherit pkgs lib;
  };
  systemdManagerWatchdog = import ./systemd-manager-watchdog.nix {
    inherit pkgs lib;
  };
  systemdNetworkConfiguration = import ./systemd-network-configuration.nix {
    inherit pkgs lib;
  };
  providerTerminalSeparation = import ./provider-terminal-separation.nix {
    inherit pkgs lib;
  };
  smokeAbilityProjection = pkgs.ability-package-smoke.abilities;
  smokeArtifactSelectors = pkgs.ability-package-smoke.contract.selectors;
  multiOutputAbilityPackage = pkgs.mkDerivation {
    pname = "multi-output-ability-package";
    version = "0";
    src = null;
    outputs = ["out" "runtime"];
    phases = [];
    abilities = ../build/fixtures/ability-module-directory;
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
  kernelPlatformSelection = import ./kernel-platform-selection.nix {
    inherit pkgs lib;
  };
  disabledRsyncProjection = pkgs.rsync.abilities;
  selectedChronySystem = mkSystem {
    modules = [
      ../../systems/_artifact-backend.nix
      ../../systems/_base-packages.nix
      ../../systems/_kernel.nix
      ../../systems/_system-manager.nix
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
  unbundledPackageModuleSystem = mkSystem {
    modules = [
      ../../systems/_artifact-backend.nix
      ../../systems/_base-packages.nix
      ../../systems/_kernel.nix
      ../../systems/_system-manager.nix
      {
        aos.packages.postgresql = {
          package = pkgs.postgresql;
          enable = true;
          bundle = false;
        };
        postgresql.enable = false;
      }
    ];
    systemName = "unbundled-package-module";
  };
  mkCheck = {
    pname,
    buildDeps ? [],
  }:
    pkgs.mkDerivation {
      inherit pname buildDeps;
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
    };
in {
  authoring = assert canonicalListType.check ["alpha" "beta"];
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
  assert deferredRuntimeString.check canonicalJson;
  assert canonicalJson._type == "aos-canonical-json";
  assert canonicalJson.source_schema == lib.abilities.types.schemaOf "canonical source" canonicalJsonSourceType;
  assert canonicalJson.max_bytes == 128;
  assert canonicalJsonNixEncoding == ''{"a":true,"z":false}'';
  assert (lib.abilities.types.schemaOf "execution path" lib.abilities.types.executionPath).syntax == "execution-path-v1";
  assert fails (lib.abilities.schemas.checkValue documentRecordSchema {unknown = true;});
  assert reservedAbilityOutputRejected "abilities";
  assert reservedAbilityOutputRejected "module";
  assert inlineAbilitiesRejected;
  assert multiOutputAbilityPackage.runtime.contract == multiOutputAbilityPackage.contract;
  assert multiOutputAbilityPackage.runtime.abilities == multiOutputAbilityPackage.abilities;
  assert multiOutputAbilityPackage.runtime.module == multiOutputAbilityPackage.module;
  assert builtins.length (lib.abilities.canonicalizeAuthenticatedPackages [
    multiOutputAbilityPackage
    multiOutputAbilityPackage.runtime
  ])
  == 1;
  assert !(pkgs.dnsutils ? abilities);
  assert !(pkgs.dnsutils ? module);
  assert pkgs.dnsutils.contract.value.package_module == null;
  assert canonicalInterface == expectedInterface;
  assert canonicalPackageStoreReadView == expectedPackageStoreReadView;
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
  assert lib.abilities.interfaceSelectorMatches descriptorAgnosticSelector testInterface;
  assert !(lib.abilities.interfaceSelectorMatches mismatchedDescriptorSelector testInterface);
  assert fails (normalizeBounded [true false null true false]);
  assert fails (normalizeBounded {oversized-member-name = true;});
  assert fails (normalizeBounded "0123456789abcdefg");
  assert lib.abilities.collectPackageOutputSelectors {
    nested = [
      (lib.abilities.packageOutput {package = "systemd";})
      (lib.abilities.packageOutput {
        package = "aos";
        output = "packageRuntime";
      })
      (lib.abilities.packageOutput {package = "systemd";})
    ];
  }
  == [
    {
      package = "aos";
      output = "packageRuntime";
    }
    {
      package = "systemd";
      output = "out";
    }
  ];
  assert fails (lib.abilities.collectPackageOutputSelectors (lib.abilities.packageOutput {}));
    mkCheck {
      pname = "aos-ability-authoring-checks";
      buildDeps = [authoringConformance];
    };

  package-services = assert kubernetesPackageServices;
  assert upgradeTransitionFixture;
  assert k3sControllerTerminal;
  assert attestationVerifierService;
  assert aosPackageRuntimeServices;
  assert configurationEvaluationService;
  assert abilityCrucibleService;
  assert abilityBoundaryObserverService;
  assert zfstoolsService;
  assert libvirtService;
  assert nginxService;
  assert mariadbService;
  assert krb5KdcService;
  assert serviceManagement;
  assert dbusService;
  assert dbusRegistrationTransition;
  assert bindService;
  assert smartmontoolsService;
  assert managedIdentityAllocation;
  assert compositionDriver;
  assert systemdPackagedUnit;
  assert systemdServiceRealization;
  assert systemdQualificationChecks;
    mkCheck {pname = "aos-ability-package-service-checks";};

  provider-realization = assert utilLinuxGetty;
  assert systemdIdentityRealization;
  assert systemdNativeResources;
  assert aosControlPlane;
  assert systemdReadiness;
  assert systemdStageMilestones;
    mkCheck {pname = "aos-ability-provider-realization-checks";};

  native-resources = assert initrdSecurityServices;
  assert initrdBootSubstrate;
  assert kernelPlatformSelection;
  assert baseKernelNative;
  assert baseNixDbNative;
  assert baseNetworkingNative;
  assert eventLogPolicy;
  assert loginSessionTracking;
  assert baseHardeningNative;
  assert securityAuditNative;
  assert securityEbpfLsmNative;
  assert securityEbpfNetworkNative;
    mkCheck {pname = "aos-ability-native-resource-checks";};

  system-selection = assert securityPolkitNative;
  assert securitySelinuxNative;
  assert securitySshNative;
  assert systemdManagerWatchdog;
  assert systemdNetworkConfiguration;
  assert providerTerminalSeparation;
  assert builtins.attrNames smokeAbilityProjection.implementations == ["default"];
  assert builtins.attrNames smokeAbilityProjection.interfaces == ["default"];
  assert builtins.length (builtins.attrNames smokeAbilityProjection.requirementTemplates) == 1;
  assert smokeArtifactSelectors
  == [
    {
      package = "ability-package-smoke";
      output = "module";
    }
    {
      package = "ability-package-smoke";
      output = "out";
    }
    {
      package = "ability-package-smoke-provider";
      output = "out";
    }
  ];
  assert builtins.length (builtins.attrNames disabledRsyncProjection.requirementTemplates) > 0;
  assert selectedChronyAbilities.instances ? "chrony:service";
  assert selectedChronyAbilities.requests ? "chrony:chronyd-lifecycle";
  assert selectedChronyAbilities.requests ? "chrony:chrony-configuration";
  assert !unbundledPackageModuleSystem.config.postgresql.enable;
  assert !(builtins.elem pkgs.postgresql unbundledPackageModuleSystem.config.environment.systemPackages);
    mkCheck {pname = "aos-ability-system-selection-checks";};

  system-packages = assert dockerService;
  assert tailscaleService;
  assert packageOptionProvenance;
  assert nftablesFirewall;
  assert containerdStaticProjection;
  assert zram;
  assert kernelModules;
  assert bootPreparationCore;
  assert nixStoreDatabase;
  assert bootPreparationProvider;
  assert bootStorageServices;
  assert packageStoreReadView;
  assert artifactBackend;
  assert stagedEnvironment;
  assert serviceFeatures;
  assert postgresqlService;
  assert securityWrappers;
  assert releaseCoordinatorService;
  assert filesystemEntryProvider;
  assert aosControllerTerminal;
  assert networkPolicyCore;
  assert selectedPackageProviderDiscovery;
  assert kernelTunables;
  assert blockStorage;
  assert baseFilesystemsNative;
  assert packageQualification;
    mkCheck {pname = "aos-ability-system-package-checks";};
}
