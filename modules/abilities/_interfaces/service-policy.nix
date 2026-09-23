##! Canonical provider-neutral service policy feature interfaces.
{
  types,
  declareInterface,
  descriptorFor,
  interfaceDocumentFromDeclaration,
  interfaceIdentity,
}: let
  localKeys = types.list {
    element = types.localKey;
    maxItems = 256;
  };
  boundedString = maxLength:
    types.string {
      inherit maxLength;
      syntax = null;
    };
  servicePrivilege = types.enum [
    "adjust-host-clock"
    "administer-host"
    "administer-network"
    "administer-resource-limits"
    "bind-privileged-network-port"
    "bypass-file-access"
    "bypass-file-read-search"
    "change-file-ownership"
    "change-group-identity"
    "change-root-directory"
    "change-user-identity"
    "create-device-node"
    "inspect-processes"
    "raw-network"
  ];
  servicePrivileges = types.list {
    element = servicePrivilege;
    maxItems = 256;
    unique = true;
  };
  privilegeBounds = types.taggedUnion {
    tag = "kind";
    variants = {
      restricted = types.record {
        fields = {
          kind = types.enum ["restricted"];
          privileges = servicePrivileges;
        };
      };
      unrestricted = types.record {
        fields = {
          kind = types.enum ["unrestricted"];
          privileges = {
            type = servicePrivileges;
            default = [];
          };
        };
      };
    };
  };
  serviceFields = {
    service = types.localKey;
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

  runtimeConditionFields = {
    privileges = types.list {
      element = types.record {
        fields = {
          privilege = servicePrivilege;
          available = types.boolean;
        };
      };
      maxItems = 256;
      unique = true;
    };
  };
  runtimeConditions = request runtimeConditionFields;
  runtimeConditionSettings = types.record {fields = runtimeConditionFields;};
  runtimeConditionsObservation = observation "runtime-conditions" runtimeConditions;

  hardeningFields = {
    allow_privilege_escalation = types.boolean;
    ambient_privileges = servicePrivileges;
    privilege_bounds = privilegeBounds;
    resource_control_delegation = types.boolean;
    resource_control_access = types.enum ["host" "private" "read-only"];
    device_access_scope = types.enum ["private" "shared"];
    host_clock_mutation = types.boolean;
    host_name_mutation = types.boolean;
    operating_system_log_access = types.boolean;
    operating_system_extension_access = types.boolean;
    operating_system_tunable_access = types.boolean;
    lock_execution_personality = types.boolean;
    writable_executable_memory = types.boolean;
    remove_interprocess_communication = {
      type = types.boolean;
      default = false;
    };
    isolation_domains = types.list {
      element = types.enum ["clock" "filesystem" "host-name" "identity" "ipc" "network" "process" "resource-control"];
      maxItems = 8;
      unique = true;
    };
    isolation_domain_creation = {
      type = types.enum ["allowed" "denied"];
      default = "allowed";
    };
    network_families = types.list {
      element = types.enum ["ipv4" "ipv6" "local" "raw-packet" "route-control"];
      maxItems = 5;
      unique = true;
    };
    memory_pressure_adjustment = types.integer {
      minimum = -1000;
      maximum = 1000;
    };
    permit_realtime = types.boolean;
    permit_elevated_file_identity = types.boolean;
    process_visibility = types.enum ["all" "same-user" "self"];
    security_label = {
      type = types.optional (boundedString 4096);
      optional = true;
    };
    operation_architectures = localKeys;
    operation_allow = localKeys;
    operation_deny = localKeys;
    denied_operation_action = {
      type = types.enum ["kill-process" "return-permission-denied"];
      default = "kill-process";
    };
    operation_profile = types.enum ["privileged" "restricted" "system-service"];
    isolated_identity_mapping = types.enum ["full" "identity" "none" "self"];
  };
  hardeningBase = request hardeningFields;
  hardeningSettingsBase = types.record {fields = hardeningFields;};
  hardeningConstraints = [
    {
      kind = "subset-unless";
      subset = ["ambient_privileges"];
      superset = ["privilege_bounds" "privileges"];
      unless_path = ["privilege_bounds" "kind"];
      unless_equals = "unrestricted";
    }
    {
      kind = "disjoint-at";
      left = ["operation_allow"];
      right = ["operation_deny"];
    }
  ];
  hardening = types.refined {
    name = "valid provider-neutral service hardening";
    description = "service hardening with bounded ambient privileges and disjoint operation policy";
    type = hardeningBase;
    constraints = hardeningConstraints;
  };
  hardeningSettings = types.refined {
    name = "valid provider-neutral service hardening settings";
    description = "service hardening settings with bounded ambient privileges and disjoint operation policy";
    type = hardeningSettingsBase;
    constraints = hardeningConstraints;
  };
  hardeningObservation = observation "hardening" hardening;

  deviceSelector = types.taggedUnion {
    tag = "kind";
    variants = {
      class = types.record {
        fields = {
          kind = types.enum ["class"];
          device_type = types.enum ["block" "character"];
          class = types.enum [
            "fuse"
            "kernel-message"
            "network-tunnel"
            "precision-time"
            "pulse-per-second"
            "real-time-clock"
          ];
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
  devicePolicyFields = {
    baseline_access = types.enum ["declared-devices-only" "standard-runtime-devices"];
    rules = types.list {
      element = types.record {
        fields = {
          selector = deviceSelector;
          read = types.boolean;
          write = types.boolean;
          create = types.boolean;
        };
      };
      maxItems = 256;
    };
  };
  devicePolicy = request devicePolicyFields;
  devicePolicySettings = types.record {fields = devicePolicyFields;};
  devicePolicyObservation = observation "device-policy" devicePolicy;

  mergeContract = descriptorFor "aos.ability.merge-contract/v1" {
    resource = "aos.service.instance";
    strategy = "typed-interface-facets";
  };
  aggregation = {
    scope = "provider-instance";
    key = "slot";
    rejectSlotCollisions = true;
    inherit mergeContract;
    controllerGroup = "service";
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
  interface = {
    alias,
    name,
    description,
    requestType,
    observationType,
    guarantees ? [],
    guaranteeAliases ? [],
  }: let
    method = {
      description = "Observes the exact service policy applied to the service.";
      inherit semantics;
      parameters = requestType;
      targetResource = "aos.service.instance";
      outputs.observation = output "Reports the exact observed service policy state." observationType;
      permittedOperations = ["observe"];
      inherit guarantees;
      outcome = {
        completionEvidence = observationType;
        observationEvidence = observationType;
        supportsRejectedBeforeEffect = true;
        indeterminate = "reconcile";
      };
    };
    declaration = declareInterface {
      inherit name description requestType guarantees aggregation;
      abi = 1;
      configurationType = null;
      outputs = {};
      methods.observe = method;
      lifecycle.persistentDeleteMethod = null;
      requiredFeatures = [];
    };
    document = interfaceDocumentFromDeclaration declaration;
  in {
    inherit alias declaration document requestType observationType;
    guarantees = guaranteeAliases;
    identity = interfaceIdentity document;
    methods = builtins.attrNames declaration.methods;
  };

  privilegeGuaranteeAlias = "core:service-runtime-condition-privilege";
  privilegeGuarantee = {
    name = "aos.guarantee.service-runtime-condition.privilege";
    version = 1;
    semantics = "the provider evaluates availability of the declared semantic service privilege";
    description = "Evaluates availability of an exact provider-neutral service privilege.";
  };
  privilegeGuaranteeIdentity = {
    inherit (privilegeGuarantee) name version;
    descriptor = descriptorFor "aos.ability.execution-guarantee/v1" {
      inherit (privilegeGuarantee) name semantics version;
    };
  };
  facets = {
    runtimeConditions = {
      alias = "service-runtime-conditions";
      facet = "runtime_conditions";
    };
    hardening = {
      alias = "service-hardening";
      facet = "hardening";
    };
    devicePolicy = {
      alias = "service-device-policy";
      facet = "device_policy";
    };
  };
  interfaces = {
    runtimeConditions = interface {
      inherit (facets.runtimeConditions) alias;
      name = "aos.service.runtime-conditions";
      description = "Requests semantic privilege-availability conditions for a service resource.";
      requestType = runtimeConditions;
      observationType = runtimeConditionsObservation;
      guarantees = [privilegeGuaranteeIdentity];
      guaranteeAliases = [privilegeGuaranteeAlias];
    };
    hardening = interface {
      inherit (facets.hardening) alias;
      name = "aos.service.hardening";
      description = "Requests provider-neutral privilege and isolation policy for a service resource.";
      requestType = hardening;
      observationType = hardeningObservation;
    };
    devicePolicy = interface {
      inherit (facets.devicePolicy) alias;
      name = "aos.service.device-policy";
      description = "Requests provider-neutral device-class and device-number access policy for a service resource.";
      requestType = devicePolicy;
      observationType = devicePolicyObservation;
    };
  };
  declarations = builtins.listToAttrs (builtins.map (selected: {
      name = selected.alias;
      value = selected.declaration;
    })
    (builtins.attrValues interfaces));
  moduleDeclarations = builtins.mapAttrs (_: declaration:
    declaration
    // {
      guarantees = builtins.map (_: privilegeGuaranteeAlias) declaration.guarantees;
      methods = builtins.mapAttrs (_: method:
        method
        // {
          guarantees = builtins.map (_: privilegeGuaranteeAlias) method.guarantees;
        })
      declaration.methods;
    })
  declarations;
  readView = {
    inherit aggregation declarations facets interfaces moduleDeclarations privilegeGuaranteeAlias;
    guarantees.${privilegeGuaranteeAlias} = privilegeGuarantee;
    types = {
      inherit devicePolicy hardening runtimeConditions servicePrivilege;
      settings = {
        inherit hardeningSettings devicePolicySettings runtimeConditionSettings;
      };
    };
  };
in {
  name = "servicePolicy";
  inherit readView;
  module.config.aos.abilities = {
    interfaces = moduleDeclarations;
    guarantees.${privilegeGuaranteeAlias} = privilegeGuarantee;
  };
}
