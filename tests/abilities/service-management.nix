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
  evaluateAs = type: value:
    (lib.evalModules {
      modules = [
        {
          options.value = lib.mkOption {inherit type;};
          config.value = value;
        }
      ];
    }).config.value;
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
  requestSchemas =
    builtins.mapAttrs
    (_: interface: interface.document.interface.request)
    interfaces;
  outputSchema = interface: method: output:
    interfaces.${interface}.document.interface.methods.${method}.outputs.${output}.schema;
  producerOutputsMatchConsumers =
    outputSchema "credentialDelivery" "deliver" "credential-path"
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
    == requestSchemas.identity.fields.supplementary_groups.element;

  expanded = serviceManagement.forService {
    inherit serviceTypes;
    consumerInstance = "consumer";
    declaration = minimalService;
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
  assert featureMethodsAreReadOnly;
  assert materializedPathSchema == executionPathSchema;
  assert producerOutputsMatchConsumers;
  assert interfaces.storageAllocation.document.interface.methods.allocate.outputs.storage-path.lifetime == "instance";
  assert interfaces.persistentStorageAllocation.document.interface.methods.allocate.outputs.storage-path.lifetime == "persistent";
  assert interfaces.persistentStorageAllocation.document.interface.methods.allocate.outputs.retained-resource.lifetime == "persistent";
  assert builtins.attrNames expanded.requests == ["main-lifecycle"];
  assert expanded.requests.main-lifecycle.consumer == "consumer";
  assert builtins.attrNames fixedPoint.config.aos.abilities.interfaces == declaredAliases; true
