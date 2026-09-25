##! Pure checks for canonical service declarations and runtime-input producers.
{lib}: let
  serviceManagement = lib.abilities.interfaces.serviceManagement;
  serviceTypes = serviceManagement.types;
  expectedMilestones = {
    localFilesystems = "aos.system.local-filesystems";
    multiUser = "aos.system.multi-user";
    hostStageReceived = "aos.boot.host-stage-received";
    imageBootCommitted = "aos.boot.image-committed";
    espReady = "aos.boot.esp-ready";
    initrdFilesystems = "aos.boot.initrd-filesystems";
    initrdRootFilesystems = "aos.boot.initrd-root-filesystems";
    rootDevice = "aos.boot.root-device";
    switchRoot = "aos.boot.switch-root";
    sysroot = "aos.boot.sysroot";
    var = "aos.boot.persistent-state";
    nixOverlay = "aos.boot.nix-overlay";
    etcOverlay = "aos.boot.etc-overlay";
    runEtc = "aos.boot.run-etc";
    deviceSettle = "aos.device.settled";
    deviceManager = "aos.device.manager-ready";
    deviceEventsTriggered = "aos.device.events-triggered";
    kernelModules = "aos.kernel.modules-loaded";
    bootIdentityValidated = "aos.boot.identity-validated";
    bootStorageUnlocked = "aos.boot.storage-unlocked";
    bootIntegrityFailure = "aos.boot.integrity-failure";
    initrdStageExecuted = "aos.boot.initrd-stage-executed";
    rootADevice = "aos.storage.root-a-device";
    storageProvisioningStateReady = "aos.storage.provisioning-state-ready";
    storageProvisioningPlanReady = "aos.storage.provisioning-plan-ready";
    verityRootMappingReady = "aos.storage.verity-root-mapping-ready";
    verityRootVerified = "aos.storage.verity-root-verified";
  };

  command = {
    executable = {
      artifact = lib.abilities.packageOutput {};
      entry_point = "bin/test-service";
      arguments = ["--foreground"];
    };
    ignore_failure = false;
  };
  minimalService = {
    service = "main";
    enabled = true;
    lifecycle = {
      description = "Service interface fixture";
      execution_model = "foreground";
      environment_files = [];
      condition = [];
      pre_start = [];
      start = [command];
      post_start = [];
      stop = [];
      post_stop = [];
      restart = "on-failure";
      restart_delay_millis = 100;
      remain_after_exit = false;
      start_timeout_millis = 1000;
      stop_timeout_millis = 1000;
    };
  };
  nestedDirectoryService =
    minimalService
    // {
      directories.managed = [
        {
          path = "rancher/k3s";
          purpose = "state";
          mode = "0755";
          retention = "persistent";
        }
      ];
    };
  configurationDirectoryService =
    minimalService
    // {
      directories.managed = [
        {
          path = "rancher/k3s";
          purpose = "configuration";
          mode = "0755";
          retention = "persistent";
        }
      ];
    };
  escapedDirectoryService =
    minimalService
    // {
      directories.managed = [
        {
          path = "../k3s";
          purpose = "state";
          mode = "0755";
          retention = "persistent";
        }
      ];
    };
  evaluateAs = type: value:
    (lib.evalModules {
      modules = [
        {
          options.value = lib.mkOption {inherit type;};
          config.value = value;
        }
      ];
    })
    .config
    .value;
  succeedsAs = type: value:
    (builtins.tryEval (builtins.deepSeq (evaluateAs type value) true)).success;
  validates = declaration:
    (builtins.tryEval (builtins.deepSeq (serviceManagement.validate serviceTypes declaration) true)).success;
  validatesActivationRelationship = relationship:
    validates (minimalService
      // {
        activation.bindings = [
          {
            name = "related-resource";
            resource = resultOf "related" "resource";
            inherit relationship;
          }
        ];
      });
  serviceIsolation = {
    privilege = "privileged";
    filesystem = "host";
    home_access = "inaccessible";
    network = "host";
    process_visibility = "host";
    termination_scope = "all-processes";
    temporary_directory = "private";
    devices = [];
    host_paths = [];
    permit_core_dumps = true;
  };
  defaultServiceIsolation = evaluateAs serviceTypes.isolation ({
      service = "smartd";
      enabled = true;
    }
    // builtins.removeAttrs serviceIsolation ["home_access"]);

  interfaces = serviceManagement.interfaces;
  lifecycleMethods = interfaces.lifecycle.document.interface.methods;
  lifecycleWrites =
    builtins.filter
    (name: lifecycleMethods.${name}.semantics.required_target_access == "exclusive-write")
    (builtins.attrNames lifecycleMethods);
  featureInterfaces = builtins.removeAttrs serviceManagement.featureInterfaces [
    "lifecycle"
    "template_definition"
  ];
  featureMethodsAreReadOnly =
    builtins.all
    (interface:
      builtins.all
      (method: method.semantics.required_target_access == "read")
      (builtins.attrValues interface.document.interface.methods))
    (builtins.attrValues featureInterfaces);

  materialization = interfaces.managedConfiguration;
  materializedPathSchema =
    materialization.document.interface.methods.materialize.outputs.execution-path.schema;
  executionPathSchema =
    lib.abilities.types.schemaOf
    "service execution path"
    serviceTypes.executionPath;
  resourceReferenceSchema =
    lib.abilities.types.schemaOf
    "activation resource reference"
    serviceTypes.resourceReference;
  prerequisiteSchema =
    interfaces.dependencies.document.interface.request.fields.prerequisites;
  instanceSelectionSchema =
    interfaces.instantiation.document.interface.request.fields.selection.variants.instance;
  requestSchemas =
    builtins.mapAttrs
    (_: interface: interface.document.interface.request)
    interfaces;
  outputSchema = interface: method: output:
    interfaces.${interface}.document.interface.methods.${method}.outputs.${output}.schema;
  producerOutputsMatchConsumers =
    interfaces.namedCredential.document.interface.outputs.resource.schema
    == requestSchemas.credentialDelivery.fields.source
    && outputSchema "credentialDelivery" "deliver" "credential-path"
    == requestSchemas.credentials.fields.views.element.fields.reference
    && outputSchema "storageView" "materialize" "storage-path"
    == requestSchemas.storage.fields.mounts.element.fields.source
    && outputSchema "hostPathView" "materialize" "host-path"
    == requestSchemas.isolation.fields.host_paths.element.fields.source
    && outputSchema "deviceView" "materialize" "device-node"
    == requestSchemas.isolation.fields.devices.element.fields.source
    && outputSchema "rootDirectoryView" "materialize" "root-directory-path"
    == requestSchemas.isolation.fields.root_directory.value
    && outputSchema "groupResolution" "resolve" "group-name"
    == requestSchemas.identity.fields.supplementary_groups.element
    && outputSchema "principalResolution" "resolve" "principal-name"
    == requestSchemas.storageAllocation.fields.owner.value
    && outputSchema "groupResolution" "resolve" "group-name"
    == requestSchemas.storageAllocation.fields.group.value
    && outputSchema "groupMembership" "reconcile" "retained-resource"
    == lib.abilities.types.resourceReference._abilitySchema
    && interfaces.persistentStorageAllocation.document.interface.outputs.planned-path.schema
    == requestSchemas.principalResolution.fields.home_directory;
  lifecycleContractsAreExecutable =
    builtins.all
    (interface: let
      declaration = interface.document.interface;
      stoppingTargets =
        builtins.map
        (method: method.target_resource)
        (builtins.filter
          (method:
            method.semantics.required_target_access
            == "exclusive-write"
            && method.semantics.stops_provider)
          (builtins.attrValues declaration.methods));
      retainedTargets =
        builtins.concatMap
        (method:
          if
            builtins.any
            (output:
              output.schema.kind
              == "resource-reference"
              && output.phase == "runtime"
              && output.visibility == "protected"
              && output.lifetime == "instance")
            (builtins.attrValues method.outputs)
          then [method.target_resource]
          else [])
        (builtins.attrValues declaration.methods);
    in
      builtins.all (target: builtins.elem target stoppingTargets) retainedTargets)
    (builtins.attrValues interfaces);
  activationOutputsAreReferences =
    outputSchema "scheduledActivation" "realize" "retained-resource"
    == resourceReferenceSchema
    && outputSchema "pathActivation" "realize" "retained-resource" == resourceReferenceSchema
    && outputSchema "mountResource" "mount" "retained-resource" == resourceReferenceSchema
    && outputSchema "automountResource" "realize" "retained-resource" == resourceReferenceSchema
    && outputSchema "swapResource" "enable" "retained-resource" == resourceReferenceSchema
    && outputSchema "activationGroup" "realize" "retained-resource" == resourceReferenceSchema;
  readinessOutputsAreReferences =
    interfaces.networkReadiness.document.interface.outputs.resource.schema
    == resourceReferenceSchema
    && interfaces.filesystemReadiness.document.interface.outputs.resource.schema
    == resourceReferenceSchema
    && interfaces.systemMilestoneReadiness.document.interface.outputs.resource.schema
    == resourceReferenceSchema;
  plannedServiceOutputsAreReferences =
    builtins.all
    (interface:
      interface.document.interface.outputs.resource.schema
      == resourceReferenceSchema
      && interface.document.interface.outputs.resource.phase == "planning"
      && interface.document.interface.outputs.resource.visibility == "protected"
      && interface.document.interface.outputs.resource.lifetime == "instance")
    [interfaces.lifecycle interfaces.templateDefinition];

  expanded = serviceManagement.forService {
    inherit serviceTypes;
    consumerInstance = "consumer";
    declaration = minimalService;
  };
  expandedWithReload = serviceManagement.forService {
    inherit serviceTypes;
    consumerInstance = "consumer";
    declaration =
      minimalService
      // {
        reload = {
          strategy = "unsupported";
          commands = [];
        };
      };
  };
  expandedWithRestartToken = serviceManagement.forService {
    inherit serviceTypes;
    consumerInstance = "consumer";
    declaration =
      minimalService
      // {
        lifecycle = minimalService.lifecycle // {restart_token = "operator-requested-restart";};
      };
  };
  expandedHelper = serviceManagement.forService {
    inherit serviceTypes;
    consumerInstance = "consumer";
    declaration = minimalService // {service = "helper";};
  };
  staticTemplateService =
    minimalService
    // {
      enabled = false;
      instantiation = {
        kind = "template";
        template = "worker";
      };
    };
  expandedStaticTemplate = serviceManagement.forService {
    inherit serviceTypes;
    consumerInstance = "consumer";
    declaration = staticTemplateService;
  };
  checkedStaticTemplate = serviceManagement.validate serviceTypes staticTemplateService;
  publicStaticTemplate =
    staticTemplateService
    // {
      manager_identity = {
        name = "worker";
        aliases = [];
      };
    };
  templateInstanceService = serviceManagement.instanceOf {
    inherit serviceTypes;
    template = staticTemplateService;
    service = "worker-blue";
    instance = "blue";
  };
  expandedTemplateInstance = serviceManagement.forService {
    inherit serviceTypes;
    consumerInstance = "consumer";
    declaration = templateInstanceService;
  };
  invalidTemplateInstanceSource = builtins.tryEval (builtins.deepSeq (serviceManagement.instanceOf {
      inherit serviceTypes;
      template = minimalService;
      service = "worker-blue";
      instance = "blue";
    })
    true);
  reusableServiceFacets = declaration:
    builtins.removeAttrs declaration ["service" "enabled" "instantiation"];
  observeOnlyKernelModules = serviceManagement.forProducer {
    consumerInstance = "consumer";
    key = "kernel-modules";
    interface = interfaces.kernelModules;
    methods = ["observe"];
    parameters = {
      modules = ["overlay"];
      required = true;
    };
  };
  declarationOnlyKernelModules = serviceManagement.forProducer {
    consumerInstance = "consumer";
    key = "declaration-only-kernel-modules";
    interface = {
      alias = interfaces.kernelModules.alias;
      declaration = interfaces.kernelModules.declaration;
    };
    methods = ["observe"];
    parameters = {
      modules = ["overlay"];
      required = true;
    };
  };
  invalidProducerMethods = methods:
    !(builtins.tryEval (builtins.deepSeq (serviceManagement.forProducer {
        consumerInstance = "consumer";
        key = "kernel-modules";
        interface = interfaces.kernelModules;
        inherit methods;
        parameters = {
          modules = ["overlay"];
          required = true;
        };
      })
      true))
    .success;
  resultOf = request: output: lib.abilities.resultOf request output;
  extendedService =
    minimalService
    // {
      lifecycle =
        minimalService.lifecycle
        // {
          start_timeout_unbounded = true;
          stop_timeout_unbounded = true;
        };
      dependencies = {
        prerequisites = [(resultOf "dependency" "resource")];
        after = [];
        before = [];
        requires = [];
        wants = [];
        requisite = [(resultOf "dependency" "resource")];
        conflicts = [];
        binds_to = [];
        part_of = [];
        upholds = [];
        required_by = [];
        wanted_by = [];
        required_mounts = [(resultOf "mount" "resource")];
        implicit_dependencies = false;
      };
      conditions.all = [
        {
          kind = "path";
          predicate = "exists";
          path = resultOf "configuration" "planned-path";
          negated = false;
        }
        {
          kind = "kernel-argument";
          argument = "example.mode=enabled";
          negated = false;
        }
        {
          kind = "mandatory-access-control";
          state = "available";
          negated = true;
        }
      ];
      instantiation = {
        kind = "singleton";
      };
      supervision = {
        startup_protocol = "notification";
        notification_access = "all-processes";
        bus_name = "org.example.Worker";
      };
      reload = {
        strategy = "signal";
        commands = [];
        signal = "HUP";
        completion = "notification";
      };
      termination = {
        signal = "TERM";
        final_signal = "KILL";
        process_id_file = resultOf "runtime-directory" "storage-path";
        send_to_all_processes = true;
      };
      watchdog = {
        timeout_millis = 30000;
        action = "restart";
      };
      start_policy = {
        accepted_exit_statuses = [0 1];
        restart_preventing_exit_statuses = [4];
        rate_interval_millis = 120000;
        rate_burst = 5;
      };
      failure_policy = {
        handlers = [(resultOf "recovery" "resource")];
        dispatch = "replace-active-goal";
      };
      concurrency = {
        group = "maintenance";
        conflict = "reject";
      };
      scheduling = {
        nice = 10;
        io_class = "idle";
        io_priority = 7;
      };
      resources = {
        open_files = {
          kind = "maximum";
          value = 1048576;
        };
        processes.kind = "unbounded";
        tasks.kind = "unbounded";
        locked_memory_bytes.kind = "unbounded";
        memory_high_bytes = {
          kind = "maximum";
          value = 1073741824;
        };
        memory_max_bytes = {
          kind = "maximum";
          value = 2147483648;
        };
      };
      environment = {
        variables = {
          INSTANCE = "blue";
          CONFIG_PATH = resultOf "configuration" "planned-path";
        };
        search_path = [
          (lib.abilities.packageOutput {package = "coreutils";})
          (lib.abilities.packageOutput {package = "iproute2";})
        ];
      };
      directories.managed = [
        {
          path = "worker-runtime";
          purpose = "runtime";
          mode = "0750";
          retention = "restart";
          owner = resultOf "principal" "principal-name";
          group = resultOf "group" "group-name";
        }
        {
          path = "worker-runtime";
          purpose = "state";
          mode = "0700";
          retention = "persistent";
        }
      ];
      activation.bindings = [
        {
          name = "periodic";
          resource = resultOf "schedule" "resource";
          relationship = "resource-triggers-service";
        }
      ];
    };
  richStaticTemplate =
    extendedService
    // {
      enabled = false;
      instantiation = {
        kind = "template";
        template = "worker-rich";
      };
    };
  richTemplateInstance = serviceManagement.instanceOf {
    inherit serviceTypes;
    template = richStaticTemplate;
    service = "worker-rich-blue";
    instance = "blue";
  };
  expandedExtended = serviceManagement.forService {
    inherit serviceTypes;
    consumerInstance = "consumer";
    declaration = extendedService;
  };
  expandedDisabledSubservice = serviceManagement.forService {
    inherit serviceTypes;
    consumerInstance = "consumer";
    declaration =
      minimalService
      // {
        service = "administration";
        enabled = false;
      };
  };
  scheduledActivation = {
    name = "periodic";
    enabled = true;
    schedule = {
      kind = "interval";
      initial_delay_millis = 1000;
      interval_millis = 60000;
    };
    persistent = true;
    accuracy_millis = 60000;
    randomized_delay_millis = 5000;
  };
  pathActivation = {
    name = "configuration-change";
    enabled = true;
    paths = [
      {
        path = resultOf "configuration" "planned-path";
        event = "changed";
      }
    ];
  };
  mountResource = {
    name = "state-mount";
    enabled = true;
    source = resultOf "state-storage" "storage-path";
    destination = resultOf "mount-point" "execution-path";
    filesystem = "ext4";
    options = ["nodev" "nosuid"];
    timeout_millis = 30000;
  };
  providerOwnedStorageMount = {
    name = "state";
    source = resultOf "state-storage" "storage-path";
    access = "read-write";
  };
  serviceIdentityStorageMount =
    providerOwnedStorageMount
    // {ownership = "service-identity";};
  invalidStorageMount =
    providerOwnedStorageMount
    // {ownership = "consumer";};
  storageRequestFor = mount: {
    service = "worker";
    enabled = true;
    mounts = [mount];
  };
  expandedWithStorage = serviceManagement.forService {
    inherit serviceTypes;
    consumerInstance = "consumer";
    declaration = minimalService // {storage.mounts = [providerOwnedStorageMount];};
  };
  placedStorageAllocation = {
    name = "state";
    purpose = "state";
    mode = "0750";
    requested_path = "/srv/state";
  };
  invalidPlacedStorageAllocation =
    placedStorageAllocation
    // {requested_path = "relative/state";};
  ownedStorageAllocation =
    placedStorageAllocation
    // {
      owner = resultOf "service-principal" "principal-name";
      group = resultOf "service-group" "group-name";
    };
  invalidOwnedStorageAllocation =
    placedStorageAllocation
    // {owner = "invalid/principal";};
  filesystemDirectory = {
    name = "wrapper-root";
    entry.kind = "directory";
    destination = "/run/aos/wrappers";
    owner = resultOf "service-principal" "principal-name";
    group = resultOf "service-group" "group-name";
    mode = "0750";
    prerequisites = [
      (resultOf "runtime-root" "resource")
    ];
  };
  invalidFilesystemDirectory =
    filesystemDirectory
    // {
      entry = {
        kind = "copied-file";
        maximum_size_bytes = 4096;
      };
    };
  maximumResourceLimit = {
    kind = "maximum";
    value = 4096;
  };
  unboundedResourceLimit.kind = "unbounded";
  namedCredentialResolution = serviceManagement.forProducer {
    consumerInstance = "registry-hub";
    key = "credential-source";
    interface = interfaces.namedCredential;
    parameters = {
      name = "hub-jwt";
      scope = "system";
    };
  };
  namedCredentialDelivery = serviceManagement.forProducer {
    consumerInstance = "registry-hub";
    key = "credential-delivery";
    interface = interfaces.credentialDelivery;
    parameters = {
      name = "jwt-secret";
      source = resultOf "credential-source" "resource";
      encrypted = false;
    };
  };
  credentialReferences = serviceManagement.forCredentialReferences {
    consumerInstance = "registry-hub";
    references = [
      {
        key = "signing-key";
        reference = {
          name = "hub-signing-key";
          scope = "system";
          encrypted = true;
        };
      }
      {
        key = "tls-certificate";
        name = "certificate";
        reference = {
          resource = (builtins.head credentialProducers).parameters.source;
          encrypted = false;
        };
      }
      {
        key = "disabled";
        reference = {};
      }
    ];
  };
  credentialProducers =
    builtins.genList (index: {
      key = "credential-${builtins.toString index}";
      parameters = {
        name = "credential-${builtins.toString index}";
        source = lib.abilities.resourceReference {
          interface = interfaces.credentialDelivery.identity;
          resource = {
            provider = lib.abilities.instanceId {
              environment = lib.abilities.environmentId {
                authority = "deployment";
                key = "service-test";
                stage = "host";
              };
              key = "credential-provider";
            };
            key = "credential-${builtins.toString index}";
          };
          operations = ["observe"];
          lifetime = "persistent";
        };
        encrypted = false;
      };
    })
    6;
  credentialBatch = serviceManagement.forProducers {
    consumerInstance = "consumer";
    interface = interfaces.credentialDelivery;
    producers = credentialProducers;
  };
  emptyCredentialBatch = serviceManagement.forProducers {
    consumerInstance = "consumer";
    interface = interfaces.credentialDelivery;
    producers = [];
  };
  principalResolution = {
    name = "service-user";
    allocation = "managed";
    requested_id = 804;
    description = "Service runtime account";
    home_directory = resultOf "service-home" "storage-path";
    login_access = "disabled";
    primary_group = resultOf "service-group" "group-name";
    supplementary_groups = [];
  };
  invalidPrincipalResolution = principalResolution // {requested_id = 0;};
  structuredConfiguration = {
    name = "structured";
    source = {
      kind = "structured-value";
      format = "json";
      document = [
        {
          kind = "object";
          path = [];
        }
        {
          kind = "string";
          path = [
            {
              kind = "key";
              value = "path";
            }
          ];
          value = lib.abilities.resultOf "runtime" "storage-path";
        }
      ];
    };
    mode = "0440";
  };
  protectedConfiguration = {
    name = "protected";
    source = {
      kind = "interpolated-text";
      fragments = [
        {
          kind = "literal";
          text = "rootpw {CLEARTEXT}";
        }
        {
          kind = "artifact-file-path";
          reference = {
            artifact = lib.abilities.packageOutput {};
            path = "etc/openldap/schema/core.schema";
          };
        }
        {
          kind = "credential-content";
          resource = lib.abilities.resultOf "root-password" "resource";
          path = lib.abilities.resultOf "root-password" "credential-path";
        }
        {
          kind = "literal";
          text = "\n";
        }
      ];
      maximum_size_bytes = 16777216;
    };
    mode = "0600";
    owner = lib.abilities.resultOf "service-principal" "principal-name";
  };
  protectedRequest = serviceManagement.forConfiguration {
    inherit serviceTypes;
    consumerInstance = "openldap";
    declaration = protectedConfiguration;
  };
  projectedStructuredConfiguration =
    structuredConfiguration
    // {
      source = serviceManagement.structuredSource {
        format = "json";
        valueType = lib.abilities.types.record {
          fields = {
            enabled = lib.abilities.types.deferredResult lib.abilities.types.boolean;
            path = lib.abilities.types.deferredResult lib.abilities.types.executionPath;
            ports = lib.abilities.types.list {
              element = lib.abilities.types.integer {
                minimum = 1;
                maximum = 65535;
              };
              maxItems = 16;
            };
          };
        };
        value = {
          enabled = lib.abilities.resultOf "enabled" "value";
          path = lib.abilities.resultOf "runtime" "storage-path";
          ports = [80 443];
        };
      };
    };
  projectedTomlConfiguration = serviceManagement.structuredSource {
    format = "toml";
    valueType = lib.abilities.types.record {
      fields.optional = {
        type = lib.abilities.types.optional lib.abilities.types.runtimeString;
        optional = true;
      };
    };
    value.optional = null;
  };
  projectedDocumentRecord = serviceManagement.structuredSource {
    format = "json";
    valueType = lib.abilities.types.documentRecord {
      keyMaxLength = 64;
      fields = {
        "@type" = lib.abilities.types.runtimeString;
        enabled = lib.abilities.types.boolean;
        attempts = lib.abilities.types.integer {
          minimum = 0;
          maximum = 16;
        };
      };
    };
    value = {
      "@type" = "type.googleapis.com/aos.test.v1.Document";
      enabled = true;
      attempts = 3;
    };
  };
  invalidStructuredConfiguration =
    structuredConfiguration
    // {
      source =
        structuredConfiguration.source
        // {
          document =
            structuredConfiguration.source.document
            ++ [
              {
                kind = "string";
                path = [
                  {
                    kind = "key";
                    value = "missing";
                  }
                  {
                    kind = "key";
                    value = "child";
                  }
                ];
                value = "bad";
              }
            ];
        };
    };
  sparseArraySource = {
    kind = "structured-value";
    format = "json";
    document = [
      {
        kind = "array";
        path = [];
      }
      {
        kind = "integer";
        path = [
          {
            kind = "index";
            value = 1;
          }
        ];
        value = 1;
      }
    ];
  };
  deferredExecutionPathSource = {
    kind = "structured-value";
    format = "json";
    document = [
      {
        kind = "execution-path";
        path = [];
        value =
          lib.abilities.resultOf "configuration" "planned-path"
          // {request = "package:configuration";};
      }
    ];
  };
  invalidExecutionPathSource =
    deferredExecutionPathSource
    // {
      document = [
        {
          kind = "execution-path";
          path = [];
          value = "relative/runtime-path";
        }
      ];
    };
  invalidExecutionPathMarkerSource =
    deferredExecutionPathSource
    // {
      document = [
        {
          kind = "execution-path";
          path = [];
          value = {
            _type = "aos-runtime-path";
            base = "relative/runtime-root";
            relative_path = "configuration.json";
          };
        }
      ];
    };
  fixedPoint = lib.evalModules {
    specialArgs = {inherit lib;};
    modules = [
      ../../modules/abilities/default.nix
      {
        aos.abilities.environment = {
          authority = "deployment";
          key = "service-test";
          stage = "host";
        };
      }
    ];
  };
  multiServiceFixedPoint = lib.evalModules {
    specialArgs = {inherit lib;};
    modules = [
      ../../modules/abilities/default.nix
      {
        aos.abilities.environment = {
          authority = "deployment";
          key = "multi-service-test";
          stage = "host";
        };
      }
    ];
    packageModules = [
      {
        name = "multi-service";
        module = {
          config.aos.abilities = lib.mkMerge [
            {instances.consumer = {};}
            expanded
            expandedHelper
          ];
        };
      }
    ];
  };
  composedServiceFixedPoint = lib.evalModules {
    specialArgs = {inherit lib;};
    modules = [
      ../../modules/abilities/default.nix
      {
        aos.abilities.environment = {
          authority = "deployment";
          key = "composed-service-test";
          stage = "host";
        };
      }
    ];
    packageModules = [
      {
        name = "policy-owner";
        module = {lib, ...}: {
          options.aos.services = lib.mkOption {
            type = lib.types.lazyAttrsOf (lib.types.submodule ({name, ...}: {
              options = lib.optionalAttrs (name == "policy-owner.main") {
                ownerPort = lib.mkOption {
                  type = lib.types.int;
                  default = 5511;
                };
              };
            }));
            default = {};
          };

          config.aos.services."policy-owner.main" = {
            enable = true;
            inherit (minimalService) lifecycle;
            resources.open_files = {
              kind = "maximum";
              value = 128;
            };
          };
        };
      }
      {
        name = "policy-extension";
        module = {lib, ...}: {
          options.aos.services = lib.mkOption {
            type = lib.types.lazyAttrsOf (lib.types.submodule ({name, ...}: {
              options = lib.optionalAttrs (name == "policy-owner.main") {
                extensionMode = lib.mkOption {
                  type = lib.types.enum ["standard" "strict"];
                  default = "strict";
                };
              };
            }));
            default = {};
          };

          config.aos.services."policy-owner.main".policy.devicePolicy = {
            baseline_access = "declared-devices-only";
            rules = [];
          };
          config.aos.services."policy-owner.main".resources.processes.kind = "unbounded";
        };
      }
    ];
  };
  sourceComposedService = lib.evalModules {
    specialArgs = {inherit lib;};
    modules = [
      ../../modules/abilities/default.nix
      {
        aos.abilities.environment = {
          authority = "deployment";
          key = "source-service-test";
          stage = "host";
        };
        aos.services.demo = {
          enable = true;
          inherit (minimalService) lifecycle;
        };
      }
    ];
  };
  composedServiceOptions =
    lib.submoduleOptionDeclarations
    composedServiceFixedPoint.options.aos.services.type._elementType
    ["aos" "services" "policy-owner.main"];
  ownerOfServiceOption = option:
    (builtins.head (builtins.filter
      (declaration: declaration.pathStr == option)
      composedServiceOptions)).owner;
  sharedGuarantee = {
    name = "aos.guarantee.test";
    version = 1;
    semantics = "The selected provider preserves the shared test invariant.";
    description = "Preserves the shared invariant used by the merge fixture.";
  };
  sharedRequirement = {
    description = "Exercises canonical merging of repeated service requirements.";
    interface = "aos.test.shared-service";
    abi = 1;
    descriptor = "sha256:2222222222222222222222222222222222222222222222222222222222222222";
    methods = ["observe"];
    guarantees = ["shared"];
    strength = "required";
    fallback = null;
  };
  multiServiceGuaranteeFixedPoint = lib.evalModules {
    specialArgs = {inherit lib;};
    modules = [../../modules/abilities/default.nix];
    packageModules = [
      {
        name = "multi-service-guarantee";
        module = {
          config.aos.abilities = lib.mkMerge [
            {guarantees.shared = sharedGuarantee;}
            {requirementTemplates.shared = sharedRequirement;}
            {requirementTemplates.shared = sharedRequirement;}
          ];
        };
      }
    ];
  };
  declaredAliases = builtins.attrNames serviceManagement.declarations;
in
  assert serviceManagement.milestones == expectedMilestones;
  assert succeedsAs serviceTypes.serviceDeclaration minimalService;
  assert succeedsAs serviceTypes.serviceDeclaration (minimalService
    // {
      lifecycle = minimalService.lifecycle // {start_timeout_millis = 604800000;};
    });
  assert !succeedsAs serviceTypes.serviceDeclaration (minimalService // {unit = "legacy.service";});
  assert !succeedsAs serviceTypes.serviceDeclaration (minimalService
    // {
      lifecycle = minimalService.lifecycle // {service_type = "simple";};
    });
  assert succeedsAs serviceTypes.serviceDeclaration (minimalService
    // {
      identity = {
        supplementary_groups = [];
        ephemeral = true;
        file_creation_mask = "0027";
      };
    });
  assert !validates (minimalService
    // {
      lifecycle = minimalService.lifecycle // {start = [command command];};
    });
  assert !validates (minimalService
    // {
      readiness = {
        mechanism = "successful-exit";
        signal_scope = "none";
        timeout_millis = 1000;
      };
    });
  assert !validates (minimalService
    // {
      readiness = {
        mechanism = "socket-accepting";
        signal_scope = "none";
        timeout_millis = 1000;
      };
    });
  assert lifecycleWrites == ["reload" "restart" "start" "stop"];
  assert builtins.attrNames interfaces.reload.document.interface.methods == ["observe"];
  assert featureMethodsAreReadOnly;
  assert lifecycleMethods.observe.outputs.observation.phase == "observation";
  assert lifecycleMethods.observe.outputs.observation.lifetime == "attempt";
  assert lifecycleMethods.start.outputs.observation.phase == "runtime";
  assert lifecycleMethods.start.outputs.observation.lifetime == "attempt";
  assert lifecycleMethods.start.outputs.retained-resource.lifetime == "instance";
  assert lifecycleMethods.start.outputs.retained-resource.phase == "runtime";
  assert interfaces.templateDefinition.document.interface.methods.materialize.outputs.retained-resource.phase
  == "runtime";
  assert materializedPathSchema == executionPathSchema;
  assert materialization.methods == ["materialize" "observe" "release"];
  assert materialization.document.interface.methods.release.semantics.required_target_access
  == "exclusive-write";
  assert materialization.document.interface.methods.release.semantics.stops_provider;
  assert protectedRequest.requests.protected.parameters == protectedConfiguration;
  assert !(builtins.tryEval (builtins.deepSeq (serviceManagement.forConfiguration {
      inherit serviceTypes;
      consumerInstance = "openldap";
      declaration = protectedConfiguration // {mode = "0640";};
    })
    true))
  .success;
  assert !(builtins.tryEval (builtins.deepSeq (serviceManagement.forConfiguration {
      inherit serviceTypes;
      consumerInstance = "openldap";
      declaration =
        protectedConfiguration
        // {
          source =
            protectedConfiguration.source
            // {
              fragments = [
                {
                  kind = "credential-content";
                  resource = lib.abilities.resultOf "first" "resource";
                  path = lib.abilities.resultOf "second" "credential-path";
                }
              ];
            };
        };
    })
    true))
  .success;
  assert producerOutputsMatchConsumers;
  assert lifecycleContractsAreExecutable;
  assert prerequisiteSchema.max_items == 256;
  assert prerequisiteSchema.unique;
  assert prerequisiteSchema.canonical_order;
  assert builtins.attrNames instanceSelectionSchema.fields
  == ["instance" "kind" "template_resource"];
  assert instanceSelectionSchema.fields.template_resource.kind == "resource-reference";
  assert activationOutputsAreReferences;
  assert readinessOutputsAreReferences;
  assert plannedServiceOutputsAreReferences;
  assert interfaces.namedCredential.document.interface.outputs.resource.phase == "planning";
  assert interfaces.namedCredential.document.interface.outputs.resource.lifetime == "instance";
  assert interfaces.namedCredential.methods == ["observe"];
  assert interfaces.principalResolution.methods == ["observe" "release" "resolve"];
  assert interfaces.groupResolution.methods == ["observe" "release" "resolve"];
  assert interfaces.groupMembership.methods == ["observe" "reconcile" "release"];
  assert interfaces.storageAllocation.document.interface.methods.allocate.outputs.storage-path.lifetime == "instance";
  assert interfaces.storageAllocation.document.interface.methods.allocate.outputs.storage-path.phase == "runtime";
  assert interfaces.storageAllocation.document.interface.outputs.planned-path.phase == "planning";
  assert interfaces.storageAllocation.document.interface.outputs.planned-path.lifetime == "instance";
  assert interfaces.persistentStorageAllocation.document.interface.methods.allocate.outputs.storage-path.lifetime == "persistent";
  assert interfaces.persistentStorageAllocation.document.interface.outputs.planned-path.phase == "planning";
  assert interfaces.persistentStorageAllocation.document.interface.outputs.planned-path.lifetime == "persistent";
  assert interfaces.persistentStorageAllocation.document.interface.methods.allocate.outputs.retained-resource.lifetime == "persistent";
  assert interfaces.persistentStorageAllocation.document.interface.lifecycle.persistent_delete_method == null;
  assert interfaces.persistentStorageAllocation.document.interface.methods.release.semantics.required_target_access == "exclusive-write";
  assert interfaces.persistentStorageAllocation.document.interface.methods.release.semantics.stops_provider;
  assert succeedsAs serviceTypes.storageAllocation placedStorageAllocation;
  assert !succeedsAs serviceTypes.storageAllocation invalidPlacedStorageAllocation;
  assert succeedsAs serviceTypes.storageAllocation ownedStorageAllocation;
  assert !succeedsAs serviceTypes.storageAllocation invalidOwnedStorageAllocation;
  assert interfaces.filesystemEntry.document.interface.outputs.planned-path.phase == "planning";
  assert interfaces.filesystemEntry.document.interface.outputs.resource.phase == "planning";
  assert interfaces.filesystemEntry.document.interface.outputs.resource.visibility == "protected";
  assert interfaces.filesystemEntry.document.interface.outputs.resource.lifetime == "instance";
  assert interfaces.filesystemEntry.document.interface.outputs.resource.schema == resourceReferenceSchema;
  assert interfaces.filesystemEntry.document.interface.methods.materialize.outputs.execution-path.phase == "runtime";
  assert interfaces.filesystemEntry.document.interface.methods.release.semantics.stops_provider;
  assert succeedsAs serviceTypes.storageAllocation placedStorageAllocation;
  assert !succeedsAs serviceTypes.storageAllocation invalidPlacedStorageAllocation;
  assert succeedsAs serviceTypes.filesystemEntry filesystemDirectory;
  assert !succeedsAs serviceTypes.filesystemEntry invalidFilesystemDirectory;
  assert succeedsAs serviceTypes.resourceLimit maximumResourceLimit;
  assert succeedsAs serviceTypes.resourceLimit unboundedResourceLimit;
  assert succeedsAs serviceTypes.isolation ({
      service = "smartd";
      enabled = true;
    }
    // serviceIsolation);
  assert defaultServiceIsolation.home_access == "host";
  assert !succeedsAs serviceTypes.isolation ({
      service = "smartd";
      enabled = true;
    }
    // serviceIsolation
    // {home_access = "hidden";});
  assert builtins.attrNames expanded.requests == ["main-lifecycle"];
  assert builtins.attrNames expandedWithReload.requests == ["main-lifecycle" "main-reload"];
  assert expanded.requirementTemplates.main-service-lifecycle.methods == ["observe" "restart" "start" "stop"];
  assert expandedWithReload.requirementTemplates.main-service-lifecycle.methods == ["observe" "reload" "restart" "start" "stop"];
  assert expandedWithRestartToken.requests.main-lifecycle.parameters.restart_token == "operator-requested-restart";
  assert multiServiceFixedPoint.config.aos.abilities.requirementTemplates."multi-service:main-service-lifecycle".methods
  == ["observe" "restart" "start" "stop"];
  assert builtins.attrNames multiServiceFixedPoint.config.aos.abilities.requests
  == ["multi-service:helper-lifecycle" "multi-service:main-lifecycle"];
  assert multiServiceGuaranteeFixedPoint.config.aos.abilities.requirementTemplates."multi-service-guarantee:shared".guarantees
  == ["multi-service-guarantee:shared"];
  assert validates staticTemplateService;
  assert validates publicStaticTemplate;
  assert builtins.attrNames expandedStaticTemplate.requirementTemplates
  == ["main-service-instantiation" "main-service-template-definition"];
  assert builtins.attrNames expandedStaticTemplate.requests
  == ["main-instantiation" "main-template_definition"];
  assert expandedStaticTemplate.requirementTemplates.main-service-template-definition.methods
  == ["materialize" "observe" "release"];
  assert expandedStaticTemplate.requests.main-template_definition.parameters.service == "main";
  assert !(expandedStaticTemplate.requests.main-template_definition.parameters ? enabled);
  assert expandedStaticTemplate.requests.main-instantiation.parameters.selection
  == staticTemplateService.instantiation;
  assert reusableServiceFacets templateInstanceService == reusableServiceFacets checkedStaticTemplate;
  assert reusableServiceFacets richTemplateInstance
  == reusableServiceFacets (serviceManagement.validate serviceTypes richStaticTemplate);
  assert templateInstanceService.enabled;
  assert templateInstanceService.instantiation
  == {
    kind = "instance";
    instance = "blue";
    template_resource = resultOf "main-template_definition" "resource";
  };
  assert builtins.attrNames expandedTemplateInstance.requests
  == ["worker-blue-instantiation" "worker-blue-lifecycle"];
  assert expandedTemplateInstance.requests.worker-blue-instantiation.parameters.selection
  == templateInstanceService.instantiation;
  assert expandedTemplateInstance.requirementTemplates.worker-blue-service-lifecycle.guarantees
  == ["core:service-template-exact-reuse"];
  assert interfaces.lifecycle.guarantees
  == ["core:service-template-exact-reuse"];
  assert expandedTemplateInstance.requirementTemplates.worker-blue-service-instantiation.guarantees == [];
  assert !invalidTemplateInstanceSource.success;
  assert !validates (staticTemplateService // {enabled = true;});
  assert observeOnlyKernelModules.requirementTemplates.kernel-modules.methods == ["observe"];
  assert declarationOnlyKernelModules.requirementTemplates.kernel-modules
  == observeOnlyKernelModules.requirementTemplates.kernel-modules;
  assert invalidProducerMethods [];
  assert invalidProducerMethods ["observe" "observe"];
  assert invalidProducerMethods ["remove"];
  assert expanded.requests.main-lifecycle.parameters.configuration_change_action == "restart";
  assert validates extendedService;
  assert builtins.attrNames expandedExtended.requests
  == [
    "main-activation"
    "main-concurrency"
    "main-conditions"
    "main-dependencies"
    "main-directories"
    "main-environment"
    "main-failure_policy"
    "main-instantiation"
    "main-lifecycle"
    "main-reload"
    "main-resources"
    "main-scheduling"
    "main-start_policy"
    "main-supervision"
    "main-termination"
    "main-watchdog"
  ];
  assert expandedDisabledSubservice.requests.administration-lifecycle.parameters.enabled == false;
  assert expandedExtended.requests.main-lifecycle.parameters.start_timeout_unbounded;
  assert expandedExtended.requests.main-dependencies.parameters.prerequisites
  == [(resultOf "dependency" "resource")];
  assert expandedExtended.requirementTemplates.main-service-conditions.guarantees
  == [
    "core:service-condition-kernel-argument"
    "core:service-condition-mandatory-access-control"
    "core:service-condition-path"
  ];
  assert expandedExtended.requests.main-environment.parameters.variables.INSTANCE == "blue";
  assert !validates (extendedService
    // {
      environment = {
        variables.PATH = "/bin";
        search_path = [(lib.abilities.packageOutput {package = "coreutils";})];
      };
    });
  assert succeedsAs serviceTypes.scheduledActivation scheduledActivation;
  assert !succeedsAs serviceTypes.scheduledActivation (builtins.removeAttrs scheduledActivation ["accuracy_millis"]);
  assert succeedsAs serviceTypes.concurrency {
    service = "worker";
    enabled = true;
    group = "maintenance";
    conflict = "reject";
  };
  assert !succeedsAs serviceTypes.concurrency {
    service = "worker";
    enabled = true;
    group = "maintenance";
    conflict = "queue";
  };
  assert succeedsAs serviceTypes.pathActivation pathActivation;
  assert succeedsAs serviceTypes.mountResource mountResource;
  assert succeedsAs serviceTypes.storage (storageRequestFor providerOwnedStorageMount);
  assert succeedsAs serviceTypes.storage (storageRequestFor serviceIdentityStorageMount);
  assert !succeedsAs serviceTypes.storage (storageRequestFor invalidStorageMount);
  assert (builtins.head expandedWithStorage.requests.main-storage.parameters.mounts).ownership == "provider";
  assert succeedsAs serviceTypes.automountResource {
    name = "state-automount";
    enabled = true;
    destination = resultOf "mount-point" "execution-path";
    idle_timeout_millis = 60000;
  };
  assert succeedsAs serviceTypes.swapResource {
    name = "swap";
    enabled = true;
    source = resultOf "swap-storage" "storage-path";
    priority = 10;
  };
  assert succeedsAs serviceTypes.activationGroup {
    name = "ready";
    enabled = true;
    description = "Ready resources";
    after = [];
    members = [(resultOf "mount" "resource")];
    required_members = [];
  };
  assert succeedsAs serviceTypes.devicePresence {
    name = "accelerator";
    device = resultOf "device" "device-node";
    timeout_millis = 30000;
  };
  assert succeedsAs serviceTypes.storageView {
    name = "containerd-socket";
    source = resultOf "runtime-storage" "resource";
    source_path = resultOf "runtime-storage" "planned-path";
    access = "read-write";
    relative_path = "containerd.sock";
  };
  assert (builtins.tryEval (builtins.deepSeq (serviceManagement.forProducer {
      consumerInstance = "consumer";
      key = "containerd-socket";
      interface = interfaces.storageView;
      parameters = {
        name = "containerd-socket";
        source = resultOf "runtime-storage" "resource";
        source_path = resultOf "runtime-storage" "planned-path";
        access = "read-write";
        relative_path = "containerd.sock";
      };
    })
    true))
  .success;
  assert !(builtins.tryEval (builtins.deepSeq (serviceManagement.forProducer {
      consumerInstance = "consumer";
      key = "foreign-socket";
      interface = interfaces.storageView;
      parameters = {
        name = "foreign-socket";
        source = resultOf "runtime-storage" "resource";
        source_path = resultOf "foreign-storage" "planned-path";
        access = "read-write";
        relative_path = "containerd.sock";
      };
    })
    true))
  .success;
  assert !succeedsAs serviceTypes.storageView {
    name = "escaped-socket";
    source = resultOf "runtime-storage" "resource";
    source_path = resultOf "runtime-storage" "planned-path";
    access = "read-write";
    relative_path = "../containerd.sock";
  };
  assert succeedsAs serviceTypes.serviceDeclaration nestedDirectoryService;
  assert succeedsAs serviceTypes.serviceDeclaration configurationDirectoryService;
  assert !succeedsAs serviceTypes.serviceDeclaration escapedDirectoryService;
  assert succeedsAs serviceTypes.filesystemReadiness {scope = "local-filesystems";};
  assert succeedsAs serviceTypes.systemMilestoneReadiness {milestone = serviceManagement.milestones.rootDevice;};
  assert succeedsAs serviceTypes.systemMilestoneReadiness {milestone = "vendor.platform-ready";};
  assert !succeedsAs serviceTypes.systemMilestoneReadiness {milestone = "root-device";};
  assert succeedsAs serviceTypes.namedCredential {
    name = "hub-jwt";
    scope = "system";
  };
  assert succeedsAs serviceTypes.credentialReference {name = "hub-signing-key";};
  assert succeedsAs serviceTypes.credentialReference {
    resource = (builtins.head credentialProducers).parameters.source;
  };
  assert !succeedsAs serviceTypes.credentialReference {
    name = "hub-signing-key";
    resource = (builtins.head credentialProducers).parameters.source;
  };
  assert builtins.all validatesActivationRelationship [
    "resource-triggers-service"
    "service-depends-on-resource"
    "service-member-of-resource"
  ];
  assert !validates (extendedService
    // {
      activation.bindings = [
        {
          name = "periodic";
          resource = resultOf "schedule" "resource";
          relationship = "trigger";
        }
      ];
    });
  assert !succeedsAs serviceTypes.serviceDeclaration (minimalService
    // {
      conditions.all = [
        {
          kind = "facility";
          facility = "mandatory-access-control";
          negated = false;
        }
      ];
    });
  assert !succeedsAs serviceTypes.serviceDeclaration (minimalService
    // {
      readiness = {
        mechanism = "process-signal";
        signal_scope = "children";
        timeout_millis = 1000;
      };
    });
  assert !validates (minimalService
    // {
      instantiation = {
        kind = "instance";
        template = "worker";
        instance = "blue";
      };
    });
  assert !validates (minimalService
    // {
      instantiation = {
        kind = "template";
        template = "worker";
        instance = "unexpected";
      };
    });
  assert !validates (minimalService
    // {
      start_policy = {
        accepted_exit_statuses = [0];
        restart_preventing_exit_statuses = [];
        rate_interval_millis = 1000;
      };
    });
  assert !validates (extendedService
    // {
      resources =
        extendedService.resources
        // {
          memory_high_bytes = {
            kind = "maximum";
            value = 4294967296;
          };
        };
    });
  assert expanded.requests.main-lifecycle.consumer == "consumer";
  assert builtins.attrNames credentialBatch.requirementTemplates == ["credential-delivery"];
  assert builtins.length (builtins.attrNames credentialBatch.requests) == 6;
  assert builtins.attrNames emptyCredentialBatch.requirementTemplates == ["credential-delivery"];
  assert emptyCredentialBatch.requests == {};
  assert namedCredentialResolution.requests.credential-source.parameters
  == {
    name = "hub-jwt";
    scope = "system";
  };
  assert namedCredentialDelivery.requests.credential-delivery.parameters.source
  == {
    _type = "aos-request-output-reference";
    request = "credential-source";
    output = "resource";
  };
  assert builtins.attrNames credentialReferences.requests
  == [
    "signing-key"
    "signing-key-source"
    "tls-certificate"
  ];
  assert credentialReferences.requests.signing-key.parameters
  == {
    name = "signing-key";
    source = {
      _type = "aos-request-output-reference";
      request = "signing-key-source";
      output = "resource";
    };
    encrypted = true;
  };
  assert credentialReferences.requests.tls-certificate.parameters
  == {
    name = "certificate";
    source = (builtins.head credentialProducers).parameters.source;
    encrypted = false;
  };
  assert succeedsAs serviceTypes.principalResolution principalResolution;
  assert !succeedsAs serviceTypes.principalResolution invalidPrincipalResolution;
  assert succeedsAs serviceTypes.configurationMaterialization structuredConfiguration;
  assert succeedsAs serviceTypes.configurationMaterialization projectedStructuredConfiguration;
  assert builtins.elem "boolean" (builtins.map (node: node.kind) projectedStructuredConfiguration.source.document);
  assert builtins.elem "execution-path" (builtins.map (node: node.kind) projectedStructuredConfiguration.source.document);
  assert projectedTomlConfiguration.document
  == [
    {
      kind = "object";
      path = [];
    }
  ];
  assert builtins.all
  (expected:
    builtins.any
    (node:
      node.kind
      == expected.kind
      && node.path
      == [
        {
          kind = "key";
          value = expected.key;
        }
      ])
    projectedDocumentRecord.document)
  [
    {
      key = "@type";
      kind = "string";
    }
    {
      key = "enabled";
      kind = "boolean";
    }
    {
      key = "attempts";
      kind = "integer";
    }
  ];
  assert !succeedsAs serviceTypes.structuredConfigurationSource invalidStructuredConfiguration.source;
  assert !succeedsAs serviceTypes.structuredConfigurationSource sparseArraySource;
  assert succeedsAs serviceTypes.structuredConfigurationSource deferredExecutionPathSource;
  assert !succeedsAs serviceTypes.structuredConfigurationSource invalidExecutionPathSource;
  assert !succeedsAs serviceTypes.structuredConfigurationSource invalidExecutionPathMarkerSource;
  assert serviceTypes.configurationMaterialization.check projectedStructuredConfiguration;
  assert !serviceTypes.configurationMaterialization.check invalidStructuredConfiguration;
  assert !serviceTypes.configurationMaterialization.check (structuredConfiguration
    // {
      source = {
        kind = "inline-text";
        content = "server configuration";
        unexpected = true;
      };
    });
  assert !serviceTypes.configurationMaterialization.check (structuredConfiguration
    // {source = {kind = "inline-text";};});
  assert !serviceTypes.configurationMaterialization.check (structuredConfiguration
    // {
      source = {
        kind = "inline-text";
        content = true;
      };
    });
  assert !(builtins.tryEval (builtins.deepSeq (serviceManagement.forConfiguration {
      inherit serviceTypes;
      consumerInstance = "consumer";
      declaration = invalidStructuredConfiguration;
    })
    true))
  .success;
  assert builtins.all
  (alias: builtins.hasAttr alias fixedPoint.config.aos.abilities.interfaces)
  declaredAliases;
  assert composedServiceFixedPoint.config.aos.abilities.requests."policy-owner:main-device_policy".parameters
  == {
    service = "main";
    enabled = true;
    baseline_access = "declared-devices-only";
    rules = [];
  };
  assert composedServiceFixedPoint.config.aos.abilities.requests."policy-owner:main-lifecycle".authority
  == {
    kind = "package";
    package = "policy-owner";
  };
  assert sourceComposedService.config.aos.abilities.requests."aos:demo-lifecycle".authority.kind
  == "system";
  assert composedServiceFixedPoint.config.aos.abilities.requests."policy-owner:main-resources".parameters
  == {
    service = "main";
    enabled = true;
    open_files = {
      kind = "maximum";
      value = 128;
    };
    processes.kind = "unbounded";
  };
  assert composedServiceFixedPoint.config.aos.services."policy-owner.main".ownerPort == 5511;
  assert composedServiceFixedPoint.config.aos.services."policy-owner.main".extensionMode == "strict";
  assert ownerOfServiceOption "ownerPort" == "policy-owner";
  assert ownerOfServiceOption "extensionMode" == "policy-extension"; true
