##! Native reusable service feature schemas, composed from ordinary option types.
{lib}: let
  optionFor = name: definition: let
    spec =
      if definition ? type
      then definition
      else {type = definition;};
  in
    lib.mkOption ({
        inherit (spec) type;
        description = "Service ${name} setting.";
      }
      // lib.optionalAttrs (spec ? default) {inherit (spec) default;}
      // lib.optionalAttrs (!(spec ? default) && (spec.optional or false)) {default = null;});

  record = {
    fields,
    optional ? [],
  }:
    lib.types.submodule {
      _module.strict = true;
      options = builtins.mapAttrs (name: value:
        optionFor name (
          if builtins.elem name optional
          then {
            type = lib.types.nullOr (
              if value ? type
              then value.type
              else value
            );
            default = null;
          }
          else value
        ))
      fields;
    };

  string = {
    maxLength,
    syntax ? null,
  }:
    lib.types.strWith {
      inherit maxLength;
      pattern =
        if syntax == "local-key-v1"
        then "[A-Za-z0-9._-]+"
        else null;
    };
  integer = {
    minimum ? null,
    maximum ? null,
  }:
    lib.types.ints.between minimum maximum;
  list = {
    element,
    maxItems,
    unique ? false,
    canonicalOrder ? false,
  }:
    lib.types.listWith {
      elemType = element;
      inherit maxItems unique canonicalOrder;
    };
  map = {
    value,
    maxEntries,
    keyMaxLength,
    keySyntax ? null,
  }:
    lib.types.attrsWith {
      elemType = value;
      inherit maxEntries keyMaxLength keySyntax;
    };
  union = {
    tag,
    variants,
  }:
    lib.types.taggedUnion tag variants;
  refined = {
    type,
    constraints,
    ...
  }:
    lib.types.refined {inherit type constraints;};

  localKeys = list {
    element = lib.types.str;
    maxItems = 256;
  };
  boundedString = maxLength:
    string {
      inherit maxLength;
      syntax = null;
    };
  servicePrivilege = lib.types.enum [
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
  servicePrivileges = list {
    element = servicePrivilege;
    maxItems = 256;
    unique = true;
  };
  privilegeBounds = union {
    tag = "kind";
    variants = {
      restricted = record {
        fields = {
          kind = lib.types.enum ["restricted"];
          privileges = servicePrivileges;
        };
      };
      unrestricted = record {
        fields = {
          kind = lib.types.enum ["unrestricted"];
          privileges = {
            type = servicePrivileges;
            default = [];
          };
        };
      };
    };
  };
  runtimeConditionFields = {
    privileges = list {
      element = record {
        fields = {
          privilege = servicePrivilege;
          available = lib.types.bool;
        };
      };
      maxItems = 256;
      unique = true;
    };
  };
  runtimeConditionSettings = record {fields = runtimeConditionFields;};

  hardeningFields = {
    allow_privilege_escalation = lib.types.bool;
    ambient_privileges = servicePrivileges;
    privilege_bounds = privilegeBounds;
    resource_control_delegation = lib.types.bool;
    resource_control_access = lib.types.enum ["host" "private" "read-only"];
    device_access_scope = lib.types.enum ["private" "shared"];
    host_clock_mutation = lib.types.bool;
    host_name_mutation = lib.types.bool;
    operating_system_log_access = lib.types.bool;
    operating_system_extension_access = lib.types.bool;
    operating_system_tunable_access = lib.types.bool;
    lock_execution_personality = lib.types.bool;
    writable_executable_memory = lib.types.bool;
    remove_interprocess_communication = {
      type = lib.types.bool;
      default = false;
    };
    isolation_domains = list {
      element = lib.types.enum ["clock" "filesystem" "host-name" "identity" "ipc" "network" "process" "resource-control"];
      maxItems = 8;
      unique = true;
    };
    isolation_domain_creation = {
      type = lib.types.enum ["allowed" "denied"];
      default = "allowed";
    };
    network_families = list {
      element = lib.types.enum ["ipv4" "ipv6" "local" "raw-packet" "route-control"];
      maxItems = 5;
      unique = true;
    };
    memory_pressure_adjustment = integer {
      minimum = -1000;
      maximum = 1000;
    };
    permit_realtime = lib.types.bool;
    permit_elevated_file_identity = lib.types.bool;
    process_visibility = lib.types.enum ["all" "same-user" "self"];
    security_label = {
      type = lib.types.nullOr (boundedString 4096);
      optional = true;
    };
    operation_architectures = localKeys;
    operation_allow = localKeys;
    operation_deny = localKeys;
    denied_operation_action = {
      type = lib.types.enum ["kill-process" "return-permission-denied"];
      default = "kill-process";
    };
    operation_profile = lib.types.enum ["privileged" "restricted" "system-service"];
    isolated_identity_mapping = lib.types.enum ["full" "identity" "none" "self"];
  };
  hardeningSettingsBase = record {fields = hardeningFields;};
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
  hardeningSettings = refined {
    name = "valid provider-neutral service hardening settings";
    description = "service hardening settings with bounded ambient privileges and disjoint operation policy";
    type = hardeningSettingsBase;
    constraints = hardeningConstraints;
  };

  deviceSelector = union {
    tag = "kind";
    variants = {
      class = record {
        fields = {
          kind = lib.types.enum ["class"];
          device_type = lib.types.enum ["block" "character"];
          class = lib.types.enum [
            "fuse"
            "kernel-message"
            "network-tunnel"
            "precision-time"
            "pulse-per-second"
            "real-time-clock"
          ];
        };
      };
      number = record {
        fields = {
          kind = lib.types.enum ["number"];
          device_type = lib.types.enum ["block" "character"];
          major = integer {
            minimum = 0;
            maximum = 4294967295;
          };
          minor = {
            type = lib.types.nullOr (integer {
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
    baseline_access = lib.types.enum ["declared-devices-only" "standard-runtime-devices"];
    rules = list {
      element = record {
        fields = {
          selector = deviceSelector;
          read = lib.types.bool;
          write = lib.types.bool;
          create = lib.types.bool;
        };
      };
      maxItems = 256;
    };
  };
  devicePolicySettings = record {fields = devicePolicyFields;};
in
  record {
    fields = {
      hardening = {
        type = lib.types.nullOr hardeningSettings;
        default = null;
      };
      devicePolicy = {
        type = lib.types.nullOr devicePolicySettings;
        default = null;
      };
      runtimeConditions = {
        type = lib.types.nullOr runtimeConditionSettings;
        default = null;
      };
    };
  }
