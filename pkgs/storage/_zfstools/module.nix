##! Package-owned scheduled ZFS snapshot services.
{
  config,
  lib,
  packageName,
  packageVersion,
  ...
}: let
  cfg = config.aos.filesystems.zfs.autoSnapshot;
  abilityTypes = lib.abilities.types;
  serviceManagement = lib.abilities.interfaces.serviceManagement;
  resultOf = lib.abilities.resultOf;
  consumerInstance = "zfs-auto-snapshot";
  storageReadiness = config.aos.storage.readinessResources;

  nonEmptyString = abilityTypes.refined {
    name = "non-empty bounded string";
    description = "a non-empty bounded string";
    type = abilityTypes.string {
      maxLength = 4096;
      syntax = null;
    };
    constraints = [
      {
        kind = "minimum-size";
        minimum = 1;
      }
    ];
  };
  intervalType = abilityTypes.record {
    fields = {
      enable = {
        type = abilityTypes.boolean;
        default = true;
      };
      calendar = nonEmptyString;
      keep = abilityTypes.integer {
        minimum = 0;
        maximum = abilityTypes.limits.maxSafeInteger;
      };
    };
  };
  datasetName = abilityTypes.refined {
    name = "ZFS dataset name";
    description = "a bounded ZFS dataset name without control characters or whitespace";
    type = abilityTypes.string {
      maxLength = 1024;
      syntax = null;
    };
    constraints = [
      {
        kind = "string-pattern";
        pattern = "[^[:space:][:cntrl:]]+";
      }
    ];
  };
  intervalNames = builtins.attrNames cfg.intervals;
  enabledIntervals = builtins.filter (name: cfg.intervals.${name}.enable) intervalNames;
  activeIntervals = builtins.filter (name: config.aos.services."zfs-auto-snapshot.${name}".enable) enabledIntervals;
  unitName = name: "zfs-auto-snapshot-${name}";

  command = artifact: entry_point: arguments: {
    executable = {
      inherit artifact entry_point arguments;
    };
    ignore_failure = false;
  };
  snapshotCommand = name:
    command
    (lib.abilities.packageOutput {})
    "bin/zfs-auto-snapshot"
    (
      lib.optional cfg.utc "--utc"
      ++ lib.optional cfg.parallel "--parallel-snapshots"
      ++ [name (builtins.toString cfg.intervals.${name}.keep)]
    );
  datasetCommand = dataset:
    command
    (lib.abilities.packageOutput {package = "zfs";})
    "sbin/zfs"
    ["set" "com.sun:auto-snapshot=true" dataset];
  lifecycle = description: start: remain_after_exit: {
    inherit description start remain_after_exit;
    execution_model = "oneshot";
    environment_files = [];
    condition = [];
    pre_start = [];
    post_start = [];
    stop = [];
    post_stop = [];
    restart = "never";
    restart_delay_millis = 0;
    configuration_change_action = "restart";
    start_timeout_millis = 90000;
    stop_timeout_millis = 90000;
  };
  isolation = {
    privilege = "privileged";
    filesystem = "read-only-system";
    home_access = "inaccessible";
    network = "none";
    process_visibility = "host";
    termination_scope = "all-processes";
    temporary_directory = "private";
    devices = [];
    host_paths = [];
    permit_core_dumps = false;
  };
  hardening = {
    allow_privilege_escalation = false;
    ambient_privileges = [];
    privilege_bounds.kind = "unrestricted";
    resource_control_delegation = false;
    resource_control_access = "read-only";
    device_access_scope = "shared";
    host_clock_mutation = false;
    host_name_mutation = false;
    operating_system_log_access = false;
    operating_system_extension_access = false;
    operating_system_tunable_access = false;
    lock_execution_personality = true;
    writable_executable_memory = false;
    remove_interprocess_communication = false;
    isolation_domains = ["filesystem"];
    network_families = ["local"];
    memory_pressure_adjustment = 0;
    permit_realtime = false;
    permit_elevated_file_identity = false;
    process_visibility = "all";
    operation_architectures = [];
    operation_allow = [];
    operation_deny = [];
    operation_profile = "privileged";
    isolated_identity_mapping = "none";
  };
  scheduling = {
    nice = 10;
    io_class = "idle";
    io_priority = 7;
  };
  prepareService = {
    policy.hardening = hardening;
    inherit consumerInstance;
    service = "prepare";
    lifecycle =
      lifecycle
      "Select ZFS datasets for automatic snapshots (${packageName} ${packageVersion})"
      (builtins.map datasetCommand cfg.datasets)
      true;
    dependencies = {
      prerequisites = storageReadiness;
      after = storageReadiness;
      before = [];
      requires = storageReadiness;
      wants = [];
    };
    inherit isolation;
  };
  schedules = serviceManagement.forProducers {
    inherit consumerInstance;
    interface = serviceManagement.interfaces.scheduledActivation;
    producers =
      builtins.map (name: {
        key = "${name}-schedule";
        parameters = {
          name = unitName name;
          enabled = true;
          schedule = {
            kind = "calendar";
            expression = cfg.intervals.${name}.calendar;
          };
          persistent = true;
          accuracy_millis = 60000;
          randomized_delay_millis = cfg.randomizedDelayMillis;
        };
      })
      activeIntervals;
  };
  intervalService = name: let
    scheduleKey = "${name}-schedule";
    dependencies = {
      prerequisites = storageReadiness;
      after = storageReadiness;
      before = [];
      requires = lib.optional (cfg.datasets != []) (resultOf "prepare-lifecycle" "resource");
      wants = storageReadiness;
    };
  in {
    policy.hardening = hardening;
    inherit consumerInstance;
    service = unitName name;
    autoStart = false;
    lifecycle =
      lifecycle
      "Create and expire ${name} ZFS snapshots (${packageName} ${packageVersion})"
      [(snapshotCommand name)]
      false;
    inherit dependencies isolation scheduling;
    activation.bindings = [
      {
        name = "schedule";
        resource = resultOf scheduleKey "resource";
        relationship = "resource-triggers-service";
      }
    ];
  };
in {
  options.aos.filesystems.zfs.autoSnapshot = {
    enable = lib.mkOption {
      type = abilityTypes.boolean;
      default = false;
      description = "Create and expire retained ZFS snapshots on a schedule.";
    };
    datasets = lib.mkOption {
      type = abilityTypes.list {
        element = datasetName;
        maxItems = 1024;
        unique = true;
        canonicalOrder = true;
      };
      default = [];
      description = "ZFS datasets marked for automatic snapshots.";
    };
    intervals = lib.mkOption {
      type = abilityTypes.map {
        keyMaxLength = 128;
        keySyntax = "local-key-v1";
        maxEntries = 64;
        value = intervalType;
      };
      default = {
        frequent = {
          calendar = "*:0/15";
          keep = 4;
        };
        hourly = {
          calendar = "hourly";
          keep = 24;
        };
        daily = {
          calendar = "daily";
          keep = 7;
        };
        weekly = {
          calendar = "weekly";
          keep = 4;
        };
        monthly = {
          calendar = "monthly";
          keep = 12;
        };
      };
      description = "Named snapshot schedules and retention counts.";
    };
    utc = lib.mkOption {
      type = abilityTypes.boolean;
      default = true;
      description = "Use UTC in generated snapshot names.";
    };
    parallel = lib.mkOption {
      type = abilityTypes.boolean;
      default = false;
      description = "Create independent dataset snapshots concurrently.";
    };
    randomizedDelayMillis = lib.mkOption {
      type = abilityTypes.integer {
        minimum = 0;
        maximum = abilityTypes.limits.maxSafeInteger;
      };
      default = 300000;
      description = "Maximum randomized delay applied to scheduled snapshot runs.";
    };
  };

  config = lib.mkMerge [
    {
      aos.services =
        lib.optionalAttrs (cfg.datasets != []) {
          "zfs-auto-snapshot.prepare" = prepareService // {enable = activeIntervals != [];};
        }
        // builtins.listToAttrs (builtins.map (name: {
            name = "zfs-auto-snapshot.${name}";
            value = (intervalService name) // {enable = cfg.enable;};
          })
          enabledIntervals);
    }
    (lib.mkIf cfg.enable {
      assertions = [
        {
          assertion = enabledIntervals != [];
          message = "aos.filesystems.zfs.autoSnapshot requires at least one enabled interval";
        }
        {
          assertion = storageReadiness != [];
          message = "aos.filesystems.zfs.autoSnapshot requires owning storage readiness resources";
        }
      ];
    })
    (lib.mkIf (activeIntervals != [] && cfg.datasets != []) {
      assertions = [
        {
          assertion = config.aos.services."zfs-auto-snapshot.prepare".enable;
          message = "enabled ZFS snapshot intervals require the dataset preparation service";
        }
      ];
    })
    (serviceManagement.producerModule {
      inherit config lib;
      producers = [schedules];
      enabled = activeIntervals != [];
    })
  ];
}
