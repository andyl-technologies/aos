##! Package-owned scheduled ZFS snapshot services.
{
  config,
  lib,
  packageName,
  packageVersion,
  ...
}: let
  cfg = config.aos.services.zfsAutoSnapshot;
  abilityTypes = lib.abilities.types;
  serviceManagement = lib.abilities.interfaces.serviceManagement;
  serviceTypes = serviceManagement.types;
  resultOf = lib.abilities.resultOf;
  consumerInstance = "zfs-auto-snapshot";

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
  unitName = name: "zfs-auto-snapshot-${name}";

  producer = key: interface: parameters:
    serviceManagement.forProducer {
      inherit consumerInstance key interface parameters;
    };
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
  linuxIsolation = {
    allow_privilege_escalation = false;
    ambient_capabilities = [];
    capability_bounds.kind = "unrestricted";
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
    remove_ipc = false;
    namespace_isolation = ["mount"];
    network_address_families = ["unix"];
    oom_score_adjust = 0;
    permit_realtime = false;
    permit_suid_sgid = false;
    process_visibility = "all";
    syscall_architectures = [];
    syscall_allow = [];
    syscall_deny = [];
    syscall_profile = "privileged";
    user_namespace_ownership = "none";
  };
  scheduling = {
    nice = 10;
    io_class = "idle";
    io_priority = 7;
  };
  prepareService = serviceManagement.forService {
    featureContributions = [
      (serviceManagement.featureContribution {
        key = "linux_isolation";
        requirementAlias = "linux-service-isolation";
        description = "Requires the selected Linux platform to enforce the declared kernel isolation policy.";
        interface = "aos.platform.linux.service-isolation";
        abi = 1;
        parameters = linuxIsolation;
      })
    ];
    inherit serviceTypes consumerInstance;
    declaration = {
      service = "prepare";
      enabled = true;
      lifecycle =
        lifecycle
        "Select ZFS datasets for automatic snapshots (${packageName} ${packageVersion})"
        (builtins.map datasetCommand cfg.datasets)
        true;
      dependencies = {
        prerequisites = cfg.storageReadiness;
        after = cfg.storageReadiness;
        before = [];
        requires = cfg.storageReadiness;
        wants = [];
      };
      inherit isolation;
    };
  };
  intervalFragments = name: let
    scheduleKey = "${name}-schedule";
    schedule = producer scheduleKey serviceManagement.interfaces.scheduledActivation {
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
    dependencies = {
      prerequisites = cfg.storageReadiness;
      after = cfg.storageReadiness;
      before = [];
      requires = lib.optional (cfg.datasets != []) (resultOf "prepare-lifecycle" "resource");
      wants = cfg.storageReadiness;
    };
    service = serviceManagement.forService {
      featureContributions = [
        (serviceManagement.featureContribution {
          key = "linux_isolation";
          requirementAlias = "linux-service-isolation";
          description = "Requires the selected Linux platform to enforce the declared kernel isolation policy.";
          interface = "aos.platform.linux.service-isolation";
          abi = 1;
          parameters = linuxIsolation;
        })
      ];
      inherit serviceTypes consumerInstance;
      declaration = {
        service = unitName name;
        enabled = false;
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
    };
  in [schedule service];
  fragments =
    lib.optional (cfg.datasets != []) prepareService
    ++ lib.concatMap intervalFragments enabledIntervals;
  contributions = builtins.map serviceManagement.splitContribution fragments;
in {
  options.aos.services.zfsAutoSnapshot = {
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
    storageReadiness = lib.mkOption {
      type = abilityTypes.list {
        element = abilityTypes.deferredResult abilityTypes.resourceReference;
        maxItems = 1025;
      };
      default = [];
      internal = true;
      description = "Exact owning storage resources that must be ready before snapshot work.";
    };
  };

  config = lib.mkMerge [
    {
      aos.abilities = lib.mkMerge (
        builtins.map (contribution: contribution.declarations) contributions
      );
    }
    (lib.mkIf cfg.enable {
      assertions = [
        {
          assertion = enabledIntervals != [];
          message = "aos.services.zfsAutoSnapshot requires at least one enabled interval";
        }
        {
          assertion = cfg.storageReadiness != [];
          message = "aos.services.zfsAutoSnapshot requires owning storage readiness resources";
        }
      ];
      aos.abilities = lib.mkMerge (
        [{instances.${consumerInstance} = {};}]
        ++ builtins.map (contribution: contribution.configured) contributions
      );
    })
  ];
}
