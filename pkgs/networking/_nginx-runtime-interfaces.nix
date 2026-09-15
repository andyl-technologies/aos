##! Canonical portable declarations for runtime interfaces shared by packages.
{
  declareInterface,
  guarantee,
  interfaceDocumentFromDeclaration,
  interfaceIdentity,
  types,
}: let
  lifecycle = {
    stableResourceIdentity = true;
    releasesEphemeralOnDisable = true;
    retainsPersistentByDefault = true;
    persistentDeleteMethod = null;
  };
  ephemeralLifecycle = lifecycle // {retainsPersistentByDefault = false;};
  aggregation = controllerGroup: {
    scope = "provider-instance";
    key = "slot";
    rejectSlotCollisions = true;
    mergeContract = null;
    inherit controllerGroup;
  };
  output = phase: schema: {
    description = "Runtime value published by the selected provider.";
    inherit schema phase;
    visibility = "protected";
    lifetime = "instance";
  };
  planningOutput = output "planning";
  runtimeOutput = output "runtime";
  string = types.string {
    maxLength = 65536;
    syntax = null;
  };
  revision = types.string {
    maxLength = 71;
    syntax = null;
  };
  localKey = types.string {
    maxLength = 128;
    syntax = "local-key-v1";
  };
  resourceMap = types.map {
    keyMaxLength = 128;
    keySyntax = "local-key-v1";
    maxEntries = 1024;
    value = types.resourceReference;
  };
  stringMap = types.map {
    keyMaxLength = 128;
    keySyntax = "local-key-v1";
    maxEntries = 1024;
    value = string;
  };
  endpoint = types.record {
    fields = {
      address = types.string {
        maxLength = 15;
        syntax = null;
      };
      port = types.integer {
        minimum = 1024;
        maximum = 65535;
      };
      transport = types.enum ["tcp"];
    };
    optional = [];
  };
  credentialView = types.record {
    fields = {
      path = types.string {
        maxLength = 4096;
        syntax = null;
      };
      version = revision;
    };
    optional = [];
  };
  storagePaths = types.record {
    fields = {
      logs = string;
      runtime = string;
      state = string;
    };
    optional = [];
  };
  consumerProbe = types.record {
    fields = {
      address = types.string {
        maxLength = 15;
        syntax = null;
      };
      execution_strategy = types.enum ["foreground-process" "managed-service"];
      port = types.integer {
        minimum = 1024;
        maximum = 65535;
      };
      tls_credential_path = types.string {
        maxLength = 4096;
        syntax = null;
      };
      tls_port = types.integer {
        minimum = 1024;
        maximum = 65535;
      };
    };
    optional = ["tls_credential_path" "tls_port"];
  };
  managedVirtualHost = types.record {
    fields = {
      backend_endpoint = endpoint;
      host = string;
      response_content = types.string {
        maxLength = 256;
        syntax = null;
      };
      response_identity = localKey;
      proxy_backend = types.boolean;
      tls = types.boolean;
      credential_version = revision;
    };
    optional = ["backend_endpoint" "credential_version" "proxy_backend"];
  };
  credentialRequest = types.record {
    fields = {
      version = revision;
      view = localKey;
    };
    optional = [];
  };
  credentialObservation = types.record {
    fields = {
      delivered = types.boolean;
      observed_version = types.optional revision;
      requested_version = revision;
      schema = types.enum ["aos.ability.credential-delivery-observation/v1"];
      view = localKey;
    };
    optional = [];
  };
  foregroundRequest = types.record {
    fields = {
      arguments = types.list {
        element = types.string {
          maxLength = 4096;
          syntax = null;
        };
        maxItems = 128;
      };
      artifact = types.artifactReference;
      entry_point = types.string {
        maxLength = 4096;
        syntax = null;
      };
    };
    optional = [];
  };
  foregroundObservation = types.record {
    fields = {
      process_identity = types.optional (types.string {
        maxLength = 1024;
        syntax = null;
      });
      running = types.boolean;
      schema = types.enum ["aos.ability.foreground-process-observation/v1"];
    };
    optional = [];
  };
  methodSemantics = name: {
    requiredTargetAccess =
      if builtins.elem name ["observe" "observe-boot" "observe-health" "validate" "verify"]
      then "read"
      else "exclusive-write";
    stopsProvider = name == "stop";
  };
  method = targetResource: name: {
    description = "Performs the ${name} operation on ${targetResource}.";
    inherit targetResource;
    semantics = methodSemantics name;
    parameters = types.boolean;
    outputs = {};
    permittedOperations = [name];
    guarantees = [];
    outcome = {
      completionEvidence = types.boolean;
      observationEvidence = types.boolean;
      supportsRejectedBeforeEffect = true;
      indeterminate = "reconcile";
    };
  };
  credentialMethod = name: outputs:
    (method "aos.credential-delivery-effects" name)
    // {
      inherit outputs;
      parameters = credentialRequest;
      outcome = {
        completionEvidence = credentialObservation;
        observationEvidence = credentialObservation;
        supportsRejectedBeforeEffect = true;
        indeterminate = "reconcile";
      };
    };
  foregroundMethod = name:
    (method "aos.foreground-process" name)
    // {
      outcome = {
        completionEvidence = foregroundObservation;
        observationEvidence = foregroundObservation;
        supportsRejectedBeforeEffect = true;
        indeterminate = "reconcile";
      };
    };
  terminal = {
    name,
    group,
    methods,
    requestType ? types.boolean,
    selectedLifecycle ? lifecycle,
    guarantees ? [],
  }:
    declareInterface {
      inherit name methods guarantees;
      description = "Native effect boundary for ${name}.";
      abi = 1;
      inherit requestType;
      outputs = {};
      lifecycle = selectedLifecycle;
      aggregation = aggregation group;
    };
  canonical = declaration: let
    document = interfaceDocumentFromDeclaration declaration;
  in {
    inherit declaration document;
    interface = interfaceIdentity document;
  };
  foregroundProcessSupervisionGuarantee = guarantee {
    name = "aos.foreground-process-supervision";
    version = 1;
    semantics = "the application-container executor retains and observes the exact declared foreground process";
  };
  managedConfigurationEffects = canonical (terminal {
    name = "aos.managed-configuration-effects";
    group = "managed-configuration-effects";
    methods = {
      prepare = method "aos.managed-configuration-effects" "prepare";
      publish = method "aos.managed-configuration-effects" "publish";
      release = method "aos.managed-configuration-effects" "release";
    };
  });
  credentialDeliveryEffects = canonical (terminal {
    name = "aos.credential-delivery-effects";
    group = "credential-delivery-effects";
    requestType = credentialRequest;
    selectedLifecycle = ephemeralLifecycle;
    methods = {
      acquire = credentialMethod "acquire" {
        credential-view = runtimeOutput credentialView;
      };
      deliver = credentialMethod "deliver" {
        credential-view = runtimeOutput credentialView;
      };
      release = credentialMethod "release" {};
    };
  });
  httpBackend = canonical (declareInterface {
    name = "aos.http-backend";
    description = "Publishes HTTP backend endpoints for a bound consumer.";
    abi = 1;
    requestType = endpoint;
    configurationType = null;
    outputs.endpoints = planningOutput (types.optional (types.map {
      keyMaxLength = 128;
      keySyntax = "local-key-v1";
      maxEntries = 1024;
      value = types.optional endpoint;
    }));
    methods = {};
    inherit lifecycle;
    guarantees = [];
    aggregation = aggregation "backend";
  });
  managedConfiguration = canonical (declareInterface {
    name = "aos.managed-configuration";
    description = "Publishes rendered configuration for a managed nginx consumer.";
    abi = 1;
    requestType = types.record {
      fields = {
        virtualHosts = types.list {
          element = managedVirtualHost;
          maxItems = 1024;
        };
        consumer_content_revision = string;
        consumer_controller_revision = string;
        consumer_instance = string;
        consumer_probe = consumerProbe;
        consumer_storage_paths = storagePaths;
      };
      optional = [];
    };
    outputs = {
      published-configurations = planningOutput resourceMap;
      rendered-configurations = planningOutput stringMap;
    };
    methods = {};
    inherit lifecycle;
    guarantees = [];
    aggregation = aggregation "configuration";
  });
  credentialDelivery = canonical (declareInterface {
    name = "aos.credential-delivery";
    description = "Publishes protected credential views for a managed nginx consumer.";
    abi = 1;
    requestType = types.record {
      fields = {
        hosts = types.list {
          element = string;
          maxItems = 1024;
        };
        version = revision;
      };
      optional = [];
    };
    outputs.credential-views = planningOutput resourceMap;
    methods = {};
    inherit lifecycle;
    guarantees = [];
    aggregation = aggregation "credentials";
  });
  serviceDefinition = canonical (declareInterface {
    name = "aos.service-definition";
    description = "Publishes service-manager resources for a managed nginx consumer.";
    abi = 1;
    requestType = types.record {
      fields = {
        configuration_revision = string;
        consumer_endpoint = string;
        service = string;
        virtual_host_count = types.integer {
          minimum = 0;
          maximum = 1024;
        };
        storage_paths = storagePaths;
      };
      optional = [];
    };
    outputs.managers = planningOutput resourceMap;
    methods = {};
    inherit lifecycle;
    guarantees = [];
    aggregation = aggregation "services";
  });
  foregroundProcess = canonical (terminal {
    name = "aos.foreground-process";
    group = "foreground-process";
    requestType = foregroundRequest;
    selectedLifecycle = ephemeralLifecycle;
    guarantees = [foregroundProcessSupervisionGuarantee];
    methods = {
      observe = foregroundMethod "observe";
      start = foregroundMethod "start";
      stop = foregroundMethod "stop";
    };
  });
in {
  inherit
    credentialDelivery
    credentialDeliveryEffects
    foregroundProcess
    foregroundProcessSupervisionGuarantee
    httpBackend
    managedConfiguration
    managedConfigurationEffects
    serviceDefinition
    ;
}
