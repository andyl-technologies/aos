##! Linux service facets implemented by the selected systemd package.
{
  lib,
  packageName,
  ...
}: let
  types = lib.abilities.types;
  serviceManagement = lib.abilities.interfaces.serviceManagement;
  localKey = types.string {
    maxLength = 128;
    syntax = "local-key-v1";
  };
  localKeys = types.list {
    element = localKey;
    maxItems = 256;
  };
  boundedString = maxLength:
    types.string {
      inherit maxLength;
      syntax = null;
    };
  capabilityName = types.refined {
    name = "Linux capability name";
    description = "An uppercase Linux capability token beginning with CAP_.";
    type = boundedString 128;
    constraints = [
      {
        kind = "string-pattern";
        pattern = "CAP_[A-Z0-9_]+";
      }
    ];
  };
  serviceFields = {
    service = localKey;
    enabled = types.boolean;
  };
  request = fields:
    types.record {
      fields = serviceFields // fields;
    };
  observation = feature: requestType:
    types.record {
      fields = {
        schema = types.enum ["aos.ability.service-${feature}-observation/v1"];
        expected = requestType;
        observed = {
          type = types.optional requestType;
          optional = true;
        };
        discrepancies = localKeys;
        state = types.enum ["applied" "disabled" "failed" "pending" "unknown"];
      };
    };
  output = description: schema: {
    inherit description schema;
    phase = "observation";
    visibility = "protected";
    lifetime = "attempt";
  };
  semantics = {
    requiredTargetAccess = "read";
    stopsProvider = false;
  };
  observeMethod = requestType: observationType: description: {
    inherit description;
    inherit semantics;
    parameters = requestType;
    targetResource = "aos.service.instance";
    outputs.observation = output "Reports the exact observed Linux service feature state." observationType;
    permittedOperations = ["observe"];
    guarantees = [];
    outcome = {
      completionEvidence = observationType;
      observationEvidence = observationType;
      supportsRejectedBeforeEffect = true;
      indeterminate = "reconcile";
    };
  };
  interface = {
    alias,
    name,
    description,
    requestType,
    observationType,
    guarantees ? [],
  }:
    lib.abilities.declareInterface {
      inherit name description requestType guarantees;
      abi = 1;
      configurationType = null;
      outputs = {};
      methods.observe =
        (observeMethod requestType observationType "Observes the Linux feature applied to the service.")
        // {
          inherit guarantees;
        };
      lifecycle.persistentDeleteMethod = null;
      aggregation = serviceManagement.aggregation;
      requiredFeatures = [];
    };

  capabilityNames = types.list {
    element = capabilityName;
    maxItems = 256;
  };
  capabilityBounds = types.taggedUnion {
    tag = "kind";
    variants = {
      restricted = types.record {
        fields = {
          kind = types.enum ["restricted"];
          capabilities = capabilityNames;
        };
      };
      unrestricted = types.record {
        fields = {
          kind = types.enum ["unrestricted"];
          capabilities = {
            type = capabilityNames;
            default = [];
          };
        };
      };
    };
  };
  linuxConditions = request {
    capabilities = types.list {
      element = types.record {
        fields = {
          capability = capabilityName;
          available = types.boolean;
        };
      };
      maxItems = 256;
    };
  };
  linuxConditionsObservation = observation "linux-conditions" linuxConditions;

  linuxIsolationBase = request {
    allow_privilege_escalation = types.boolean;
    ambient_capabilities = capabilityNames;
    capability_bounds = capabilityBounds;
    control_group_delegation = types.boolean;
    control_group_access = types.enum ["host" "private" "read-only"];
    device_namespace = types.enum ["private" "shared"];
    kernel_clock_mutation = types.boolean;
    kernel_hostname_mutation = types.boolean;
    kernel_log_access = types.boolean;
    kernel_module_access = types.boolean;
    kernel_tunable_access = types.boolean;
    lock_personality = types.boolean;
    memory_write_execute = types.boolean;
    remove_ipc = {
      type = types.boolean;
      default = false;
    };
    namespace_isolation = types.list {
      element = types.enum ["cgroup" "ipc" "mount" "network" "pid" "time" "user" "uts"];
      maxItems = 8;
    };
    namespace_creation = {
      type = types.enum ["allowed" "denied"];
      default = "allowed";
    };
    network_address_families = types.list {
      element = types.enum ["ipv4" "ipv6" "netlink" "packet" "unix"];
      maxItems = 5;
    };
    oom_score_adjust = types.integer {
      minimum = -1000;
      maximum = 1000;
    };
    permit_realtime = types.boolean;
    permit_suid_sgid = types.boolean;
    process_visibility = types.enum ["all" "same-user" "self"];
    security_label = {
      type = types.optional (boundedString 4096);
      optional = true;
    };
    syscall_architectures = localKeys;
    syscall_allow = types.list {
      element = boundedString 128;
      maxItems = 256;
    };
    syscall_deny = types.list {
      element = boundedString 128;
      maxItems = 256;
    };
    syscall_denial_action = {
      type = types.enum ["kill-process" "return-permission-denied"];
      default = "kill-process";
    };
    syscall_profile = types.enum ["privileged" "restricted" "system-service"];
    user_namespace_ownership = types.enum ["full" "identity" "none" "self"];
  };
  linuxIsolation = types.refined {
    name = "valid Linux service isolation";
    description = "Linux service isolation with unique sets, bounded ambient capabilities, and disjoint syscall policy";
    type = linuxIsolationBase;
    constraints = [
      {
        kind = "unique-at";
        path = ["namespace_isolation"];
      }
      {
        kind = "unique-at";
        path = ["network_address_families"];
      }
      {
        kind = "subset-unless";
        subset = ["ambient_capabilities"];
        superset = ["capability_bounds" "capabilities"];
        unless_path = ["capability_bounds" "kind"];
        unless_equals = "unrestricted";
      }
      {
        kind = "disjoint-at";
        left = ["syscall_allow"];
        right = ["syscall_deny"];
      }
    ];
  };
  linuxIsolationObservation = observation "linux-isolation" linuxIsolation;

  linuxDeviceSelector = types.taggedUnion {
    tag = "kind";
    variants = {
      class = types.record {
        fields = {
          kind = types.enum ["class"];
          device_type = types.enum ["block" "character"];
          class = localKey;
        };
      };
      number = types.record {
        fields = {
          kind = types.enum ["number"];
          device_type = types.enum ["block" "character"];
          major = types.integer {
            minimum = 0;
            maximum = 4294967295;
          };
          minor = {
            type = types.optional (types.integer {
              minimum = 0;
              maximum = 4294967295;
            });
            optional = true;
          };
        };
      };
    };
  };
  linuxDevicePolicy = request {
    baseline_access = types.enum ["standard-runtime-devices" "declared-devices-only"];
    rules = types.list {
      element = types.record {
        fields = {
          selector = linuxDeviceSelector;
          read = types.boolean;
          write = types.boolean;
          create_node = types.boolean;
        };
      };
      maxItems = 256;
    };
  };
  linuxDevicePolicyObservation = observation "linux-device-policy" linuxDevicePolicy;

  serviceFacets = {
    linuxConditions = {
      alias = "linux-service-conditions";
      facet = "linux_conditions";
    };
    linuxIsolation = {
      alias = "linux-service-isolation";
      facet = "linux_isolation";
    };
    linuxDevicePolicy = {
      alias = "linux-service-device-policy";
      facet = "linux_device_policy";
    };
  };

  capabilityGuaranteeAlias = "linux-service-condition-capability";
  capabilityGuarantee = {
    name = "aos.guarantee.linux-service-condition.capability";
    version = 1;
    semantics = "the provider evaluates availability of the declared Linux capability name";
    description = "Evaluates availability of an exact Linux capability for a service condition.";
  };
  interfaces = {
    ${serviceFacets.linuxConditions.alias} = interface {
      inherit (serviceFacets.linuxConditions) alias;
      name = "aos.platform.linux.service-conditions";
      description = "Contributes Linux capability-availability conditions to a service resource.";
      requestType = linuxConditions;
      observationType = linuxConditionsObservation;
      guarantees = [capabilityGuaranteeAlias];
    };
    ${serviceFacets.linuxIsolation.alias} = interface {
      inherit (serviceFacets.linuxIsolation) alias;
      name = "aos.platform.linux.service-isolation";
      description = "Contributes Linux-specific kernel isolation policy to a service resource.";
      requestType = linuxIsolation;
      observationType = linuxIsolationObservation;
    };
    ${serviceFacets.linuxDevicePolicy.alias} = interface {
      inherit (serviceFacets.linuxDevicePolicy) alias;
      name = "aos.platform.linux.service-device-policy";
      description = "Contributes Linux cgroup device-class and device-number access policy to a service resource.";
      requestType = linuxDevicePolicy;
      observationType = linuxDevicePolicyObservation;
    };
  };
  artifact = lib.abilities.packageOutput {};
  implementation = alias: declaration: {
    description = "Realizes ${declaration.name} through the selected systemd service controller.";
    interface = alias;
    inherit artifact;
    methods = ["observe"];
    guarantees = declaration.guarantees;
    requirements = {};
    providerModule = {
      artifact = lib.abilities.packageOutput {output = "module";};
      path = "provider/systemd.nix";
    };
    desiredType = null;
    requiredFeatures = [];
  };
in {
  options.aos.systemd.serviceFacets = lib.mkOption {
    type = lib.types.attrsOf (lib.types.submodule {
      config._module.strict = true;
      options = {
        alias = lib.mkOption {type = types.localKey;};
        facet = lib.mkOption {type = types.localKey;};
      };
    });
    default = {};
    readOnly = true;
    internal = true;
    description = "Selected system-manager service facet declarations.";
  };

  config.aos.abilities = {
    guarantees.${capabilityGuaranteeAlias} = capabilityGuarantee;
    interfaces = interfaces;
    implementations = builtins.mapAttrs implementation interfaces;
  };
  config.aos.systemd.serviceFacets = serviceFacets;
}
