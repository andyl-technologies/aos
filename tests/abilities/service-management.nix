##! Pure checks for canonical service declarations and runtime-input producers.
{lib}: let
  serviceManagement = lib.abilities.interfaces.serviceManagement;
  serviceTypes = serviceManagement.types;

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
  nestedDirectoryService = minimalService // {
    directories.managed = [{
      path = "rancher/k3s";
      purpose = "state";
      mode = "0755";
      retention = "persistent";
    }];
  };
  escapedDirectoryService = minimalService // {
    directories.managed = [{
      path = "../k3s";
      purpose = "state";
      mode = "0755";
      retention = "persistent";
    }];
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

  interfaces = serviceManagement.interfaces;
  lifecycleMethods = interfaces.lifecycle.document.interface.methods;
  lifecycleWrites =
    builtins.filter
    (name: lifecycleMethods.${name}.semantics.required_target_access == "exclusive-write")
    (builtins.attrNames lifecycleMethods);
  featureInterfaces = builtins.removeAttrs serviceManagement.featureInterfaces ["lifecycle"];
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
  requestSchemas =
    builtins.mapAttrs
    (_: interface: interface.document.interface.request)
    interfaces;
  outputSchema = interface: method: output:
    interfaces.${interface}.document.interface.methods.${method}.outputs.${output}.schema;
  producerOutputsMatchConsumers =
    interfaces.namedCredential.document.interface.outputs.credential-resource.schema
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
    && interfaces.persistentStorageAllocation.document.interface.outputs.planned-path.schema
    == requestSchemas.principalResolution.fields.home_directory;
  producerInterfacesReleaseEphemeralResources =
    builtins.all
    (interface:
      interface.document.interface.lifecycle.releases_ephemeral_on_disable
      && interface.document.interface.methods.release.semantics.required_target_access
      == "exclusive-write"
      && interface.document.interface.methods.release.semantics.stops_provider)
    (builtins.attrValues {
      inherit
        (interfaces)
        credentialDelivery
        storageView
        storageAllocation
        hostPathView
        deviceView
        rootDirectoryView
        principalResolution
        groupResolution
        scheduledActivation
        pathActivation
        mountResource
        automountResource
        swapResource
        activationGroup
        ;
    });
  activationOutputsAreReferences =
    outputSchema "scheduledActivation" "realize" "activation-resource"
    == resourceReferenceSchema
    && outputSchema "pathActivation" "realize" "activation-resource" == resourceReferenceSchema
    && outputSchema "mountResource" "mount" "mount-resource" == resourceReferenceSchema
    && outputSchema "automountResource" "realize" "automount-resource" == resourceReferenceSchema
    && outputSchema "swapResource" "enable" "swap-resource" == resourceReferenceSchema
    && outputSchema "activationGroup" "realize" "activation-resource" == resourceReferenceSchema;
  readinessOutputsAreReferences =
    interfaces.networkReadiness.document.interface.outputs.readiness-resource.schema
    == resourceReferenceSchema
    && interfaces.filesystemReadiness.document.interface.outputs.readiness-resource.schema
    == resourceReferenceSchema;

  expanded = serviceManagement.forService {
    inherit serviceTypes;
    consumerInstance = "consumer";
    declaration = minimalService;
  };
  splitExpanded = serviceManagement.splitContribution expanded;
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
        after = [];
        before = [];
        requires = [];
        wants = [];
        requisite = [(resultOf "dependency" "retained-resource")];
        conflicts = [];
        binds_to = [];
        part_of = [];
        upholds = [];
        required_by = [];
        wanted_by = [];
        required_mounts = [(resultOf "mount" "mount-resource")];
        implicit_dependencies = false;
      };
      conditions.all = [
        {
          kind = "path";
          predicate = "exists";
          path = resultOf "configuration" "execution-path";
          negated = false;
        }
        {
          kind = "kernel-argument";
          argument = "example.mode=enabled";
          negated = false;
        }
        {
          kind = "facility";
          facility = "mandatory-access-control";
          negated = true;
        }
      ];
      linux_conditions.capabilities = [
        {
          capability = "CAP_SYS_TIME";
          available = true;
        }
      ];
      instantiation = {
        kind = "instance";
        template = "worker";
        instance = "blue";
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
        handlers = [(resultOf "recovery" "activation-resource")];
        dispatch = "replace-active-goal";
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
          CONFIG_PATH = resultOf "configuration" "execution-path";
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
          resource = resultOf "schedule" "activation-resource";
          relationship = "trigger";
        }
      ];
      linux_device_policy = {
        baseline_access = "standard-runtime-devices";
        rules = [
          {
            selector = {
              kind = "class";
              device_type = "character";
              class = "ptp";
            };
            read = true;
            write = true;
            create_node = false;
          }
        ];
      };
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
  systemOwnedService = serviceManagement.forService {
    inherit serviceTypes;
    consumerInstance = "system:bind";
    declaration =
      minimalService
      // {
        lifecycle =
          minimalService.lifecycle
          // {
            start = [
              {
                executable =
                  command.executable
                  // {
                    arguments = [(resultOf "configuration" "execution-path")];
                  };
                ignore_failure = false;
              }
            ];
          };
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
    randomized_delay_millis = 5000;
  };
  pathActivation = {
    name = "configuration-change";
    enabled = true;
    paths = [
      {
        path = resultOf "configuration" "execution-path";
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
  restrictedCapabilityBounds = {
    kind = "restricted";
    capabilities = ["CAP_NET_BIND_SERVICE"];
  };
  unrestrictedCapabilityBounds.kind = "unrestricted";
  maximumResourceLimit = {
    kind = "maximum";
    value = 4096;
  };
  unboundedResourceLimit.kind = "unbounded";
  linuxIsolation = {
    allow_privilege_escalation = false;
    ambient_capabilities = ["CAP_NET_BIND_SERVICE"];
    capability_bounds = restrictedCapabilityBounds;
    control_group_delegation = false;
    control_group_access = "read-only";
    device_namespace = "shared";
    kernel_clock_mutation = false;
    kernel_hostname_mutation = false;
    kernel_log_access = false;
    kernel_module_access = false;
    kernel_tunable_access = false;
    lock_personality = true;
    memory_write_execute = false;
    namespace_isolation = [];
    network_address_families = ["ipv4" "ipv6" "unix"];
    oom_score_adjust = 0;
    permit_realtime = false;
    permit_suid_sgid = false;
    process_visibility = "all";
    syscall_architectures = [];
    syscall_allow = [];
    syscall_deny = [];
    syscall_profile = "system-service";
    user_namespace_ownership = "none";
  };
  invalidLinuxIsolation =
    linuxIsolation
    // {
      ambient_capabilities = ["CAP_SYS_ADMIN"];
    };
  invalidLinuxConditions.capabilities = [
    {
      capability = "sys-time";
      available = true;
    }
  ];
  invalidLinuxDevicePolicy = {
    baseline_access = "standard-runtime-devices";
    rules = [
      {
        selector = {
          kind = "number";
          device_type = "character";
          major = -1;
        };
        read = true;
        write = false;
        create_node = false;
      }
    ];
  };
  namedCredentialResolution = serviceManagement.forProducer {
    consumerInstance = "system:registry-hub";
    key = "credential-source";
    interface = interfaces.namedCredential;
    parameters = {
      name = "hub-jwt";
      scope = "system";
    };
  };
  namedCredentialDelivery = serviceManagement.forProducer {
    consumerInstance = "system:registry-hub";
    key = "credential-delivery";
    interface = interfaces.credentialDelivery;
    parameters = {
      name = "jwt-secret";
      source = resultOf "credential-source" "credential-resource";
      encrypted = false;
    };
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
  systemCredentialBatch = serviceManagement.forProducers {
    consumerInstance = "system:secrets";
    interface = interfaces.credentialDelivery;
    producers = credentialProducers;
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
          kind = "artifact-path";
          reference = {
            artifact = lib.abilities.packageOutput {};
            path = "etc/openldap/schema/core.schema";
          };
        }
        {
          kind = "credential-content";
          resource = lib.abilities.resultOf "root-password" "retained-resource";
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
          lib.abilities.resultOf "configuration" "execution-path"
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
  sharedGuarantee = {
    name = "aos.guarantee.test";
    version = 1;
    descriptor = "sha256:1111111111111111111111111111111111111111111111111111111111111111";
  };
  sharedRequirement = {
    description = "Exercises canonical merging of repeated service requirements.";
    interface = "aos.test.shared-service";
    abi = 1;
    descriptor = "sha256:2222222222222222222222222222222222222222222222222222222222222222";
    methods = ["observe"];
    guarantees = [sharedGuarantee];
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
            {requirementTemplates.shared = sharedRequirement;}
            {requirementTemplates.shared = sharedRequirement;}
          ];
        };
      }
    ];
  };
  declaredAliases = builtins.attrNames serviceManagement.declarations;
in
  assert succeedsAs serviceTypes.serviceDeclaration minimalService;
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
  assert materializedPathSchema == executionPathSchema;
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
                  resource = lib.abilities.resultOf "first" "retained-resource";
                  path = lib.abilities.resultOf "second" "credential-path";
                }
              ];
            };
        };
    })
    true))
  .success;
  assert producerOutputsMatchConsumers;
  assert producerInterfacesReleaseEphemeralResources;
  assert activationOutputsAreReferences;
  assert readinessOutputsAreReferences;
  assert interfaces.namedCredential.document.interface.outputs.credential-resource.phase == "planning";
  assert interfaces.namedCredential.document.interface.outputs.credential-resource.lifetime == "instance";
  assert !interfaces.namedCredential.document.interface.lifecycle.releases_ephemeral_on_disable;
  assert interfaces.namedCredential.methods == ["observe"];
  assert interfaces.storageAllocation.document.interface.methods.allocate.outputs.storage-path.lifetime == "instance";
  assert interfaces.storageAllocation.document.interface.methods.allocate.outputs.storage-path.phase == "runtime";
  assert interfaces.storageAllocation.document.interface.outputs.planned-path.phase == "planning";
  assert interfaces.storageAllocation.document.interface.outputs.planned-path.lifetime == "instance";
  assert interfaces.persistentStorageAllocation.document.interface.methods.allocate.outputs.storage-path.lifetime == "persistent";
  assert interfaces.persistentStorageAllocation.document.interface.outputs.planned-path.phase == "planning";
  assert interfaces.persistentStorageAllocation.document.interface.outputs.planned-path.lifetime == "persistent";
  assert interfaces.persistentStorageAllocation.document.interface.methods.allocate.outputs.retained-resource.lifetime == "persistent";
  assert !interfaces.persistentStorageAllocation.document.interface.lifecycle.releases_ephemeral_on_disable;
  assert interfaces.persistentStorageAllocation.document.interface.lifecycle.retains_persistent_by_default;
  assert interfaces.persistentStorageAllocation.document.interface.lifecycle.persistent_delete_method == null;
  assert interfaces.persistentStorageAllocation.document.interface.methods.release.semantics.required_target_access == "exclusive-write";
  assert interfaces.persistentStorageAllocation.document.interface.methods.release.semantics.stops_provider;
  assert !interfaces.networkReadiness.document.interface.lifecycle.releases_ephemeral_on_disable;
  assert !interfaces.filesystemReadiness.document.interface.lifecycle.releases_ephemeral_on_disable;
  assert succeedsAs serviceTypes.storageAllocation placedStorageAllocation;
  assert !succeedsAs serviceTypes.storageAllocation invalidPlacedStorageAllocation;
  assert succeedsAs serviceTypes.storageAllocation ownedStorageAllocation;
  assert !succeedsAs serviceTypes.storageAllocation invalidOwnedStorageAllocation;
  assert succeedsAs serviceTypes.capabilityBounds restrictedCapabilityBounds;
  assert succeedsAs serviceTypes.capabilityBounds unrestrictedCapabilityBounds;
  assert succeedsAs serviceTypes.resourceLimit maximumResourceLimit;
  assert succeedsAs serviceTypes.resourceLimit unboundedResourceLimit;
  assert validates (minimalService // {linux_isolation = linuxIsolation;});
  assert !validates (minimalService // {linux_isolation = invalidLinuxIsolation;});
  assert succeedsAs serviceTypes.linuxConditions {
    service = "clock";
    enabled = true;
    capabilities = [
      {
        capability = "CAP_SYS_TIME";
        available = true;
      }
    ];
  };
  assert !succeedsAs serviceTypes.linuxConditions ({
      service = "clock";
      enabled = true;
    }
    // invalidLinuxConditions);
  assert succeedsAs serviceTypes.linuxDevicePolicy {
    service = "clock";
    enabled = true;
    baseline_access = "standard-runtime-devices";
    rules = extendedService.linux_device_policy.rules;
  };
  assert !succeedsAs serviceTypes.linuxDevicePolicy ({
      service = "clock";
      enabled = true;
    }
    // invalidLinuxDevicePolicy);
  assert builtins.attrNames expanded.requests == ["main-lifecycle"];
  assert builtins.attrNames splitExpanded.declarations == ["requirementTemplates"];
  assert splitExpanded.declarations.requirementTemplates == expanded.requirementTemplates;
  assert builtins.attrNames splitExpanded.configured == ["requests"];
  assert splitExpanded.configured.requests == expanded.requests;
  assert builtins.attrNames expandedWithReload.requests == ["main-lifecycle" "main-reload"];
  assert expanded.requirementTemplates.service-lifecycle.methods == ["observe" "restart" "start" "stop"];
  assert expandedWithReload.requirementTemplates.service-lifecycle.methods == ["observe" "reload" "restart" "start" "stop"];
  assert expandedWithRestartToken.requests.main-lifecycle.parameters.restart_token == "operator-requested-restart";
  assert multiServiceFixedPoint.config.aos.abilities.requirementTemplates."multi-service:service-lifecycle".methods
  == ["observe" "restart" "start" "stop"];
  assert builtins.attrNames multiServiceFixedPoint.config.aos.abilities.requests
  == ["multi-service:helper-lifecycle" "multi-service:main-lifecycle"];
  assert multiServiceGuaranteeFixedPoint.config.aos.abilities.requirementTemplates."multi-service-guarantee:shared".guarantees
  == [sharedGuarantee];
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
    "main-conditions"
    "main-dependencies"
    "main-directories"
    "main-environment"
    "main-failure_policy"
    "main-instantiation"
    "main-lifecycle"
    "main-linux_conditions"
    "main-linux_device_policy"
    "main-reload"
    "main-resources"
    "main-scheduling"
    "main-start_policy"
    "main-supervision"
    "main-termination"
    "main-watchdog"
  ];
  assert expandedDisabledSubservice.requests.administration-lifecycle.parameters.enabled == false;
  assert systemOwnedService.requests."system:main-lifecycle".consumer == "system:bind";
  assert systemOwnedService.requests."system:main-lifecycle".requirement == "system:service-lifecycle";
  assert (builtins.head systemOwnedService.requests."system:main-lifecycle".parameters.start).executable.arguments
  == [
    {
      _type = "aos-request-output-reference";
      request = "system:configuration";
      output = "execution-path";
    }
  ];
  assert expandedExtended.requests.main-lifecycle.parameters.start_timeout_unbounded;
  assert expandedExtended.requests.main-environment.parameters.variables.INSTANCE == "blue";
  assert !validates (extendedService
    // {
      environment = {
        variables.PATH = "/bin";
        search_path = [(lib.abilities.packageOutput {package = "coreutils";})];
      };
    });
  assert succeedsAs serviceTypes.scheduledActivation scheduledActivation;
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
    members = [(resultOf "mount" "mount-resource")];
  };
  assert succeedsAs serviceTypes.devicePresence {
    name = "accelerator";
    device = resultOf "device" "device-node";
    timeout_millis = 30000;
  };
  assert succeedsAs serviceTypes.storageView {
    name = "containerd-socket";
    source = resultOf "runtime-storage" "retained-resource";
    access = "read-write";
    relative_path = "containerd.sock";
  };
  assert !succeedsAs serviceTypes.storageView {
    name = "escaped-socket";
    source = resultOf "runtime-storage" "retained-resource";
    access = "read-write";
    relative_path = "../containerd.sock";
  };
  assert succeedsAs serviceTypes.serviceDeclaration nestedDirectoryService;
  assert !succeedsAs serviceTypes.serviceDeclaration escapedDirectoryService;
  assert succeedsAs serviceTypes.filesystemReadiness {scope = "local-filesystems";};
  assert succeedsAs serviceTypes.namedCredential {
    name = "hub-jwt";
    scope = "system";
  };
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
  assert builtins.attrNames systemCredentialBatch.requirementTemplates == ["system:credential-delivery"];
  assert builtins.length (builtins.attrNames systemCredentialBatch.requests) == 6;
  assert systemCredentialBatch.requests."system:credential-0".consumer == "system:secrets";
  assert namedCredentialResolution.requests."system:credential-source".parameters
  == {
    name = "hub-jwt";
    scope = "system";
  };
  assert namedCredentialDelivery.requests."system:credential-delivery".parameters.source
  == {
    _type = "aos-request-output-reference";
    request = "system:credential-source";
    output = "credential-resource";
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
  assert !(builtins.tryEval (builtins.deepSeq (serviceManagement.forConfiguration {
      inherit serviceTypes;
      consumerInstance = "consumer";
      declaration = invalidStructuredConfiguration;
    })
    true))
  .success;
  assert builtins.attrNames fixedPoint.config.aos.abilities.interfaces == declaredAliases; true
