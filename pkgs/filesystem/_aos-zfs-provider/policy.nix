##! OpenZFS memory and failure policy owned by the native provider package.
{
  config,
  lib,
  packageFor,
  ...
}: let
  cfg = config.aos.filesystems.zfs;
  memory = cfg.memory;
  failure = cfg.failurePolicy;
  abilityTypes = lib.abilities.types;
  serviceManagement = lib.abilities.interfaces.serviceManagement;
  consumerInstance = "zfs-storage";
  resultOf = lib.abilities.resultOf;
  mib = 1048576;
  gib = 1073741824;

  ceilingArcMax = memory.maxBytes * memory.arcPercent / 100;
  ceilingDnodeLimit = ceilingArcMax * memory.dnodePercent / 100;
  ceilingDirtyDataMax = memory.maxBytes * memory.dirtyDataPercent / 100;
  budgetShare = memory.arcPercent + memory.scrubPercent + memory.dirtyDataPercent;

  loadTimeParameters =
    {
      "spl.spl_kmem_cache_obj_per_slab" = 1;
      "zfs.zfs_arc_max" = ceilingArcMax;
      "zfs.zfs_arc_sys_free" = memory.systemFreeReserve;
      "zfs.zfs_arc_dnode_limit" = ceilingDnodeLimit;
      "zfs.zfs_dirty_data_max" = ceilingDirtyDataMax;
    }
    // lib.optionalAttrs memory.limitAbdScatter {
      "zfs.zfs_abd_scatter_max_order" = 0;
    };
  packagedVersion =
    builtins.unsafeDiscardStringContext
    (
      packageFor (lib.abilities.packageOutput {package = "zfs";})
    ).version;
  knownIssueParameters =
    lib.optionalAttrs (
      cfg.knownIssueWorkarounds
      && builtins.compareVersions packagedVersion "2.4.4" <= 0
    ) {
      # OpenZFS 2.4.x can fault in its LZ4 trial pass before Zstd compression.
      "zfs.zstd_earlyabort_pass" = 0;
    };
  effectiveParameters = loadTimeParameters // knownIssueParameters;
  parameterArguments =
    lib.mapAttrsToList (
      name: value: "${name}=${toString value}"
    )
    effectiveParameters;

  producer = key: interface: parameters:
    serviceManagement.forProducer {
      inherit consumerInstance key interface parameters;
    };
  kernelModules = producer "zfs-kernel-module" serviceManagement.interfaces.kernelModules {
    modules = ["zfs"];
    required = true;
  };
  runtimeTunables =
    lib.optionalAttrs cfg.fragmentationDefenses {"vm.defrag_mode" = "1";}
    // lib.optionalAttrs failure.panicOnOops {
      "kernel.panic_on_oops" = "1";
      "kernel.panic" = toString failure.panicTimeout;
    };
  tunables = producer "zfs-kernel-tunables" lib.abilities.interfaces.kernelTunables.interface {
    values = runtimeTunables;
    dependencies = [(resultOf "zfs-kernel-module" "resource")];
  };

  program = {
    artifact = lib.abilities.packageOutput {};
    entry_point = "bin/aos-zfs-memory-policy";
    arguments = [];
  };
  command = arguments: {
    executable = program // {inherit arguments;};
    ignore_failure = false;
  };
  policyArguments = [
    (toString memory.maxBytes)
    (toString memory.maxPercent)
    (toString memory.arcPercent)
    (toString memory.dnodePercent)
    (toString memory.scrubPercent)
    (toString memory.dirtyDataPercent)
    (toString memory.systemFreeReserve)
    (toString memory.committedPercentLimit)
  ];
  service = key: description: arguments: prerequisites: {
    inherit consumerInstance;
    service = key;
    lifecycle = {
      inherit description;
      execution_model = "oneshot";
      environment_files = [];
      condition = [];
      pre_start = [];
      start = [(command arguments)];
      post_start = [];
      stop = [];
      post_stop = [];
      restart = "never";
      restart_delay_millis = 0;
      configuration_change_action = "restart";
      remain_after_exit = true;
      start_timeout_millis = 90000;
      stop_timeout_millis = 90000;
    };
    dependencies = {
      inherit prerequisites;
      after = prerequisites;
      before = [];
      requires = prerequisites;
      wants = [];
    };
    isolation = {
      privilege = "privileged";
      filesystem = "host";
      network = "none";
      process_visibility = "host";
      termination_scope = "main-process";
      temporary_directory = "private";
      devices = [];
      host_paths = [];
      permit_core_dumps = false;
    };
  };
  memoryPolicy = service "zfs-memory-policy" "Apply the bounded OpenZFS memory policy" (["apply"] ++ policyArguments) [
    (resultOf "zfs-kernel-module" "resource")
    (resultOf "zfs-kernel-tunables" "resource")
  ];
  verification = service "zfs-verify-parameters" "Verify the running OpenZFS memory and failure policy" (["verify"] ++ policyArguments) [
    (resultOf "zfs-memory-policy-lifecycle" "resource")
  ];
in {
  options.aos.filesystems.zfs = {
    memory = {
      maxBytes = lib.mkOption {
        type = abilityTypes.integer {
          minimum = 512 * mib;
          maximum = abilityTypes.limits.maxSafeInteger;
        };
        default = 8 * gib;
        description = "Absolute ceiling in bytes on OpenZFS kernel memory.";
      };
      maxPercent = lib.mkOption {
        type = abilityTypes.integer {
          minimum = 1;
          maximum = 80;
        };
        default = 25;
        description = "Additional OpenZFS memory ceiling as a percentage of installed RAM.";
      };
      arcPercent = lib.mkOption {
        type = abilityTypes.integer {
          minimum = 1;
          maximum = 100;
        };
        default = 70;
        description = "Share of the memory budget available to the ARC.";
      };
      dnodePercent = lib.mkOption {
        type = abilityTypes.integer {
          minimum = 1;
          maximum = 100;
        };
        default = 25;
        description = "Share of the ARC available to dnode metadata.";
      };
      scrubPercent = lib.mkOption {
        type = abilityTypes.integer {
          minimum = 1;
          maximum = 100;
        };
        default = 10;
        description = "Share of the memory budget available to scrub and resilver queues.";
      };
      dirtyDataPercent = lib.mkOption {
        type = abilityTypes.integer {
          minimum = 1;
          maximum = 100;
        };
        default = 15;
        description = "Share of the memory budget available to dirty write data.";
      };
      systemFreeReserve = lib.mkOption {
        type = abilityTypes.integer {
          minimum = 0;
          maximum = abilityTypes.limits.maxSafeInteger;
        };
        default = 1 * gib;
        description = "Bytes of system memory the ARC keeps free by shrinking.";
      };
      committedPercentLimit = lib.mkOption {
        type = abilityTypes.integer {
          minimum = 1;
          maximum = 90;
        };
        default = 60;
        description = "Maximum installed-RAM share committed by OpenZFS and compressed swap.";
      };
      limitAbdScatter = lib.mkOption {
        type = abilityTypes.boolean;
        default = true;
        description = "Restrict ARC buffer scatter chunks to single pages.";
      };
    };
    failurePolicy = {
      panicOnOops = lib.mkOption {
        type = abilityTypes.boolean;
        default = true;
        description = "Panic and reboot when a kernel oops can leave the storage stack wedged.";
      };
      panicTimeout = lib.mkOption {
        type = abilityTypes.integer {
          minimum = 0;
          maximum = 3600;
        };
        default = 10;
        description = "Seconds to wait after a panic before rebooting.";
      };
      verifyParameters = lib.mkOption {
        type = abilityTypes.boolean;
        default = true;
        description = "Verify that the running kernel retains the configured OpenZFS parameters.";
      };
    };
    fragmentationDefenses = lib.mkOption {
      type = abilityTypes.boolean;
      default = true;
      description = "Retain proactive kernel defenses against unmovable-allocation fragmentation.";
    };
    moduleParameters = lib.mkOption {
      type = abilityTypes.list {
        element = abilityTypes.string {
          maxLength = 4096;
          syntax = null;
        };
        maxItems = 64;
        unique = true;
        canonicalOrder = true;
      };
      readOnly = true;
      internal = true;
      description = "Exact OpenZFS module parameters derived from the bounded memory policy.";
    };
    knownIssueWorkarounds = lib.mkOption {
      type = abilityTypes.boolean;
      default = true;
      description = "Apply version-bound parameters for known defects in the packaged OpenZFS release.";
    };
  };

  config = lib.mkMerge [
    {
      assertions = [
        {
          assertion = budgetShare <= 100;
          message = "OpenZFS ARC, scrub, and dirty-data shares must total at most 100 percent";
        }
        {
          assertion = memory.systemFreeReserve < memory.maxBytes;
          message = "OpenZFS systemFreeReserve must be smaller than maxBytes";
        }
        {
          assertion = memory.maxPercent <= memory.committedPercentLimit;
          message = "the OpenZFS budget alone exceeds committedPercentLimit";
        }
      ];
      aos.filesystems.zfs.moduleParameters = parameterArguments;
      aos.services = {
        "zfs-storage.zfs-memory-policy" = memoryPolicy // {enable = cfg.enable;};
        "zfs-storage.zfs-verify-parameters" =
          verification
          // {
            enable = cfg.enable && failure.verifyParameters;
          };
      };
    }
    (serviceManagement.producerModule {
      inherit config lib;
      producers = [kernelModules tunables];
      enabled = cfg.enable;
    })
  ];
}
