##! modules/base/zfs-memory.nix — Bounded ZFS memory and fail-fast policy
##!
##! OpenZFS sizes most of its memory structures from installed RAM rather than
##! from pool capacity, so stock defaults that are unremarkable on a 64 GiB
##! server permit hundreds of gigabytes on a large host. `zfs_arc_max` bounds
##! only one of those structures, and it is a target the ARC may exceed while
##! metadata is pinned and cannot be evicted.
##!
##! This module makes ZFS a bounded tenant of RAM instead. One budget
##! (`aos.filesystems.zfs.memory`) caps total ZFS kernel memory, and every
##! module parameter derives from it. The budget is the lesser of an absolute
##! ceiling and a share of installed RAM, so one configuration is safe on both
##! a small edge device and a large build host.
##!
##! The module also fixes the allocation geometry that fragments physical
##! memory (one object per SPL slab), keeps the kernel's fragmentation
##! defenses in place, and makes a storage-path kernel fault reboot the machine
##! rather than wedge it. Its verification service fails loudly when the
##! running kernel does not carry the configured load-time parameters, which is
##! the state a host is left in after applying configuration without rebooting.
{
  config,
  lib,
  pkgs,
  ...
}: let
  cfg = config.aos.filesystems.zfs;
  memory = cfg.memory;
  failure = cfg.failurePolicy;

  mib = 1048576;
  gib = 1073741824;

  # Shares of the budget spent on each ZFS structure. Their sum is asserted
  # below so the derived parameters cannot collectively exceed the budget.
  budgetShares = [memory.arcPercent memory.scrubPercent memory.dirtyDataPercent];
  totalSharePercent = lib.foldl' (total: share: total + share) 0 budgetShares;

  # Byte values derived from the absolute ceiling. The boot-time policy service
  # recomputes them against installed RAM and lowers them when the percentage
  # cap binds first; these are the values in force from module load until that
  # service runs, so they have to be safe on their own.
  ceilingArcMax = memory.maxBytes * memory.arcPercent / 100;
  ceilingDnodeLimit = ceilingArcMax * memory.dnodePercent / 100;
  ceilingDirtyDataMax = memory.maxBytes * memory.dirtyDataPercent / 100;
  ceilingScrubBudget = memory.maxBytes * memory.scrubPercent / 100;

  # Parameters read only when their module is inserted. SPL slab geometry in
  # particular is fixed as each cache is created, so it cannot be corrected at
  # runtime: a host that applied configuration without rebooting keeps the old
  # allocation policy until it does.
  loadTimeParameters =
    {
      # One object per slab keeps a 1 MiB ZFS buffer cache in roughly 1 MiB
      # allocations rather than the roughly 8 MiB that the default of eight
      # produces. Large unmovable slab allocations are what strand physical
      # memory: one live object pins its whole slab, compaction cannot
      # relocate it, and high-order free blocks stop coalescing. OpenZFS
      # documents the tradeoff as slower individual allocations in exchange
      # for a smaller footprint and faster reclaim.
      "spl.spl_kmem_cache_obj_per_slab" = 1;

      "zfs.zfs_arc_max" = ceilingArcMax;
      "zfs.zfs_arc_sys_free" = memory.systemFreeReserve;
      "zfs.zfs_arc_dnode_limit" = ceilingDnodeLimit;
      "zfs.zfs_dirty_data_max" = ceilingDirtyDataMax;
    }
    // lib.optionalAttrs memory.limitAbdScatter {
      # ABD scatter chunks above one page reintroduce higher-order allocations
      # on the write path. Order 0 keeps every scatter chunk movable.
      "zfs.zfs_abd_scatter_max_order" = 0;
    };

  # Workarounds tied to the pinned OpenZFS release rather than to host policy.
  # Each names the upstream report it answers so it can be dropped when the pin
  # moves past the fix.
  zfsVersion = cfg.package.version or "0";
  versionAtMost = bound: builtins.compareVersions zfsVersion bound <= 0;

  knownIssueParameters =
    # OpenZFS issue 17516: the LZ4 trial pass that OpenZFS runs ahead of Zstd
    # compression has faulted on an unmapped page inside a borrowed ABD source
    # buffer, oopsing the writer thread. Skipping the early-abort pass avoids
    # that path at a small compression-ratio cost.
    lib.optionalAttrs (cfg.knownIssueWorkarounds && versionAtMost "2.4.4") {
      "zfs.zstd_earlyabort_pass" = 0;
    };

  effectiveParameters = loadTimeParameters // knownIssueParameters;

  parameterArguments =
    lib.mapAttrsToList (name: value: "${name}=${toString value}") effectiveParameters;

  # Kernel command-line names are `<module>.<parameter>`; sysfs drops the
  # module prefix into a directory component.
  sysfsPath = name: let
    parts = lib.splitString "." name;
  in "/sys/module/${builtins.head parts}/parameters/${lib.concatStringsSep "." (builtins.tail parts)}";

  # Ceilings the policy service is allowed to lower once RAM is known, so
  # verification checks them for "at most" rather than for equality.
  loweredAtRuntime = [
    "zfs.zfs_arc_max"
    "zfs.zfs_arc_dnode_limit"
    "zfs.zfs_dirty_data_max"
  ];

  verifiedParameters =
    lib.mapAttrsToList (name: value: {
      inherit name;
      path = sysfsPath name;
      expected = toString value;
      comparison =
        if lib.elem name loweredAtRuntime
        then "check_at_most"
        else "check_exact";
    })
    effectiveParameters;

  scriptPath = lib.makeBinPath [pkgs.coreutils pkgs.grep];

  # Recompute the budget against installed RAM and apply the parameters
  # OpenZFS expresses as divisors of physical memory, which cannot be derived
  # at build time. Runs at boot and again whenever configuration changes.
  memoryPolicy = pkgs.writeShellScriptBin "aos-zfs-memory-policy" ''
    set -euo pipefail

    PATH=${scriptPath}''${PATH:+:$PATH}

    mem_total_kib=$(grep -E '^MemTotal:' /proc/meminfo | tr -dc '0-9')
    if [ -z "$mem_total_kib" ]; then
      echo "aos-zfs-memory-policy: cannot read MemTotal from /proc/meminfo" >&2
      exit 1
    fi
    mem_total=$((mem_total_kib * 1024))

    # The budget is the lesser of the absolute ceiling and the configured share
    # of RAM. The ceiling protects large hosts, where RAM-scaled defaults are
    # what grow without bound; the share protects small hosts, where a fixed
    # ceiling could approach installed memory.
    budget=${toString memory.maxBytes}
    proportional=$((mem_total / 100 * ${toString memory.maxPercent}))
    if [ "$proportional" -lt "$budget" ]; then
      budget=$proportional
    fi

    arc_max=$((budget / 100 * ${toString memory.arcPercent}))
    dnode_limit=$((arc_max / 100 * ${toString memory.dnodePercent}))
    dirty_data_max=$((budget / 100 * ${toString memory.dirtyDataPercent}))
    scrub_budget=$((budget / 100 * ${toString memory.scrubPercent}))
    if [ "$scrub_budget" -lt 1 ]; then
      scrub_budget=1
    fi

    write_parameter() {
      target=$1
      value=$2
      if [ ! -w "$target" ]; then
        echo "aos-zfs-memory-policy: parameter is not writable: $target" >&2
        return 1
      fi
      printf '%s\n' "$value" > "$target"
    }

    # Never raise a ceiling that module load already established; only tighten
    # it when the proportional cap binds first.
    lower_parameter() {
      target=$1
      desired=$2
      current=$(cat "$target")
      if [ "$current" -eq 0 ] || [ "$desired" -lt "$current" ]; then
        write_parameter "$target" "$desired"
      fi
    }

    lower_parameter /sys/module/zfs/parameters/zfs_arc_max "$arc_max"
    lower_parameter /sys/module/zfs/parameters/zfs_arc_dnode_limit "$dnode_limit"
    lower_parameter /sys/module/zfs/parameters/zfs_dirty_data_max "$dirty_data_max"

    # OpenZFS expresses the scrub and resilver sort queue as a divisor of
    # physical memory, so the absolute budget has to be converted back into a
    # divisor here. Clamp it into the range the module accepts.
    scan_fact=$((mem_total / scrub_budget))
    if [ "$scan_fact" -lt 2 ]; then
      scan_fact=2
    fi
    if [ "$scan_fact" -gt 10000 ]; then
      scan_fact=10000
    fi

    write_parameter /sys/module/zfs/parameters/zfs_scan_mem_lim_fact "$scan_fact"

    # The soft limit bounds the queue mid-scan and must not exceed the hard
    # limit, so it tracks the same divisor.
    if [ -w /sys/module/zfs/parameters/zfs_scan_mem_lim_soft_fact ]; then
      write_parameter /sys/module/zfs/parameters/zfs_scan_mem_lim_soft_fact "$scan_fact"
    fi

    printf 'aos-zfs-memory-policy: budget %s MiB (arc %s MiB, dirty %s MiB, scrub %s MiB, scan_mem_lim_fact %s)\n' \
      "$((budget / 1048576))" "$((arc_max / 1048576))" \
      "$((dirty_data_max / 1048576))" "$((scrub_budget / 1048576))" "$scan_fact"
  '';

  # A host can apply configuration without rebooting, silently leaving
  # load-time parameters at their previous values. Report that rather than
  # letting a host run indefinitely on an allocation policy it has replaced.
  verifyParameters = pkgs.writeShellScriptBin "aos-zfs-verify-parameters" ''
    set -uo pipefail

    PATH=${scriptPath}''${PATH:+:$PATH}

    status=0

    read_parameter() {
      path=$1
      if [ ! -r "$path" ]; then
        return 1
      fi
      cat "$path"
    }

    check_exact() {
      name=$1
      path=$2
      expected=$3
      if ! actual=$(read_parameter "$path"); then
        echo "aos-zfs-verify-parameters: missing parameter $name ($path)" >&2
        status=1
        return
      fi
      if [ "$actual" != "$expected" ]; then
        echo "aos-zfs-verify-parameters: $name is $actual, expected $expected." \
          "This parameter is only read when the module loads; reboot to apply it." >&2
        status=1
      fi
    }

    check_at_most() {
      name=$1
      path=$2
      ceiling=$3
      if ! actual=$(read_parameter "$path"); then
        echo "aos-zfs-verify-parameters: missing parameter $name ($path)" >&2
        status=1
        return
      fi
      if [ "$actual" -gt "$ceiling" ]; then
        echo "aos-zfs-verify-parameters: $name is $actual, above the configured ceiling $ceiling." \
          "Reboot to apply the configured budget." >&2
        status=1
      fi
    }

    ${lib.concatMapStringsSep "\n" (parameter: "${parameter.comparison} ${lib.escapeShellArg parameter.name} ${lib.escapeShellArg parameter.path} ${lib.escapeShellArg parameter.expected}") verifiedParameters}

    # ZFS and compressed swap both consume RAM. Letting each claim a large
    # share leaves reclaim pushing ARC pressure into swap that is itself
    # memory, which deepens fragmentation while free-memory accounting still
    # looks healthy. Check the commitments against reality rather than against
    # a symbolic size expression that cannot be evaluated at build time.
    mem_total_kib=$(grep -E '^MemTotal:' /proc/meminfo | tr -dc '0-9')
    if [ -n "$mem_total_kib" ]; then
      mem_total=$((mem_total_kib * 1024))
      committed=${toString memory.maxBytes}
      proportional=$((mem_total / 100 * ${toString memory.maxPercent}))
      if [ "$proportional" -lt "$committed" ]; then
        committed=$proportional
      fi

      for disksize in /sys/block/zram*/disksize; do
        [ -r "$disksize" ] || continue
        committed=$((committed + $(cat "$disksize")))
      done

      headroom=$((mem_total / 100 * ${toString memory.committedPercentLimit}))
      if [ "$committed" -gt "$headroom" ]; then
        echo "aos-zfs-verify-parameters: ZFS and zram commit $((committed / 1048576)) MiB," \
          "above the $((headroom / 1048576)) MiB limit for this host." \
          "Lower aos.filesystems.zfs.memory or aos.zram.size." >&2
        status=1
      fi
    fi

    exit "$status"
  '';
in {
  options.aos.filesystems.zfs = {
    ## Absolute bounds on the kernel memory OpenZFS may hold.
    ##
    ## Every derived module parameter is a share of this budget. The effective
    ## budget is `min(maxBytes, maxPercent% of installed RAM)`, resolved at boot
    ## by `aos-zfs-memory-policy.service`.
    memory = {
      maxBytes = lib.mkOption {
        type = lib.types.addCheck lib.types.int (value: value >= 512 * mib);
        default = 8 * gib;
        description = ''
          Absolute ceiling, in bytes, on the kernel memory OpenZFS may hold
          across the ARC, dnode and dbuf caches, write buffering, and scrub
          sorting. This is deliberately an absolute number rather than a share
          of RAM: OpenZFS's own RAM-scaled defaults are what let a large host
          give tens or hundreds of gigabytes to a pool that does not need them.
          Raise it for cache-sensitive workloads on hosts with memory to spare.
        '';
      };

      maxPercent = lib.mkOption {
        type = lib.types.addCheck lib.types.int (value: value > 0 && value <= 80);
        default = 25;
        description = ''
          Additional cap on the budget as a percentage of installed RAM. The
          effective budget is the lesser of this and `maxBytes`, so the same
          configuration stays safe on a small edge device and on a large
          server.
        '';
      };

      arcPercent = lib.mkOption {
        type = lib.types.addCheck lib.types.int (value: value > 0 && value <= 100);
        default = 70;
        description = "Share of the budget available to the ARC (`zfs_arc_max`).";
      };

      dnodePercent = lib.mkOption {
        type = lib.types.addCheck lib.types.int (value: value > 0 && value <= 100);
        default = 25;
        description = ''
          Share of the ARC that dnode metadata may occupy
          (`zfs_arc_dnode_limit`). Metadata-heavy workloads are the ones that
          drive the ARC past its target, because pinned metadata cannot be
          evicted on demand.
        '';
      };

      scrubPercent = lib.mkOption {
        type = lib.types.addCheck lib.types.int (value: value > 0 && value <= 100);
        default = 10;
        description = ''
          Share of the budget available to scrub and resilver sort queues.
          OpenZFS defaults this queue to one twentieth of physical RAM, which
          is tens of gigabytes on a large host regardless of pool size.
        '';
      };

      dirtyDataPercent = lib.mkOption {
        type = lib.types.addCheck lib.types.int (value: value > 0 && value <= 100);
        default = 15;
        description = ''
          Share of the budget available for buffering dirty write data
          (`zfs_dirty_data_max`).
        '';
      };

      systemFreeReserve = lib.mkOption {
        type = lib.types.addCheck lib.types.int (value: value >= 0);
        default = 1 * gib;
        description = ''
          Bytes of system memory the ARC keeps free by shrinking
          (`zfs_arc_sys_free`). This is a reclaim threshold rather than a
          reservation.
        '';
      };

      committedPercentLimit = lib.mkOption {
        type = lib.types.addCheck lib.types.int (value: value > 0 && value <= 90);
        default = 60;
        description = ''
          Maximum share of installed RAM that the ZFS budget and compressed
          swap may commit together. Verified against the running host, where
          the zram device size is known, because `aos.zram.size` is an
          arithmetic expression the module system cannot evaluate.
        '';
      };

      limitAbdScatter = lib.mkOption {
        type = lib.types.bool;
        default = true;
        description = ''
          Restrict ARC buffer scatter chunks to single pages
          (`zfs_abd_scatter_max_order`). Higher orders return unmovable
          multi-page allocations to the write path, the same fragmentation
          pressure that oversized SPL slabs create.
        '';
      };
    };

    ## Behavior when a kernel fault occurs, and when the running kernel does
    ## not carry the configured parameters.
    failurePolicy = {
      panicOnOops = lib.mkOption {
        type = lib.types.bool;
        default = true;
        description = ''
          Panic and reboot on a kernel oops rather than killing the faulting
          thread. A fault in a ZFS worker leaves the storage stack wedged while
          the rest of the system stays nominally alive, which is the worst
          outcome for an appliance: I/O stalls, the host stops making progress,
          and nothing recovers without an operator. AOS images are A/B with
          boot counting and rollback, so rebooting is the cheap response.
        '';
      };

      panicTimeout = lib.mkOption {
        type = lib.types.addCheck lib.types.int (value: value >= 0);
        default = 10;
        description = ''
          Seconds to wait after a panic before rebooting, leaving time for the
          trace to reach the console and persistent storage. Zero disables the
          automatic reboot.
        '';
      };

      verifyParameters = lib.mkOption {
        type = lib.types.bool;
        default = true;
        description = ''
          Verify at boot that the running kernel carries the configured
          load-time ZFS parameters, and fail the unit when it does not. SPL
          slab geometry is fixed as caches are created, so applying
          configuration without rebooting leaves a host running its previous
          allocation policy with no other visible signal.
        '';
      };
    };

    ## Keep the kernel's own defenses against physical-memory fragmentation.
    fragmentationDefenses = lib.mkOption {
      type = lib.types.bool;
      default = true;
      description = ''
        Enable proactive anti-fragmentation reclaim (`vm.defrag_mode`) and keep
        fragmentation-driven watermark boosting at the kernel default. ZFS
        allocates long-lived unmovable kernel memory that compaction cannot
        relocate, so contiguous free regions have to be preserved rather than
        recovered after the fact.
      '';
    };

    ## Apply parameter workarounds for known defects in the pinned OpenZFS.
    knownIssueWorkarounds = lib.mkOption {
      type = lib.types.bool;
      default = true;
      description = ''
        Apply module parameters that work around open defects in the pinned
        OpenZFS release. Each workaround names its upstream report and is
        version-gated, so it stops applying once the pin moves past the fix.
      '';
    };
  };

  config = lib.mkIf cfg.enable {
    assertions = [
      {
        assertion = totalSharePercent <= 100;
        message =
          "aos.filesystems.zfs.memory shares total ${toString totalSharePercent}% of the budget;"
          + " arcPercent, scrubPercent and dirtyDataPercent must sum to at most 100";
      }
      {
        assertion = memory.systemFreeReserve < memory.maxBytes;
        message = "aos.filesystems.zfs.memory.systemFreeReserve must be smaller than maxBytes";
      }
      {
        assertion = memory.maxPercent <= memory.committedPercentLimit;
        message =
          "aos.filesystems.zfs.memory.maxPercent exceeds committedPercentLimit;"
          + " the ZFS budget alone would breach the host's total memory commitment";
      }
      {
        # A zeroed watermark boost removes the kernel's fragmentation-driven
        # reclaim, which is what keeps higher-order allocations satisfiable
        # once unmovable ZFS slabs are in play.
        assertion =
          !cfg.fragmentationDefenses
          || (config.aos.kernel.sysctl."vm.watermark_boost_factor" or "15000") != "0";
        message =
          "vm.watermark_boost_factor is disabled while ZFS fragmentation defenses are enabled;"
          + " zeroing it removes the reclaim that keeps contiguous memory available for ZFS allocations";
      }
    ];

    # Load-time module parameters. These are baked into the signed UKI, so a
    # budget change requires an image rebuild and a reboot, which is exactly
    # the condition the verification service reports on.
    aos.boot.kernelParams = parameterArguments;

    aos.kernel.sysctl = lib.mkMerge [
      (lib.mkIf cfg.fragmentationDefenses {
        # Keep higher-order free blocks available rather than trying to recover
        # them after unmovable allocations have scattered. Linux documents
        # enabling this early in boot, because fragmentation that has set in
        # can be effectively permanent.
        "vm.defrag_mode" = "1";
      })
      (lib.mkIf failure.panicOnOops {
        "kernel.panic_on_oops" = "1";
        "kernel.panic" = toString failure.panicTimeout;
      })
    ];

    # A wedged storage stack can leave userspace running while no progress is
    # possible. The hardware watchdog is the backstop for the case where the
    # panic path itself cannot complete.
    aos.monitoring.hardware.enable = lib.mkDefault true;

    systemd.services."aos-zfs-memory-policy" = {
      description = "Apply the bounded ZFS memory policy";
      wantedBy = ["local-fs.target"];
      before = ["local-fs.target" "zfs-mount.service"];
      after = ["zfs-import.service"];
      unitConfig.ConditionPathIsDirectory = "/sys/module/zfs/parameters";
      serviceConfig = {
        Type = "oneshot";
        RemainAfterExit = true;
      };
      # Live in-place upgrades change the derived values without a reboot;
      # re-running the policy applies every runtime-writable parameter.
      reloadTriggers = [memoryPolicy];
      script = lib.getExe memoryPolicy;
    };

    systemd.services."aos-zfs-verify-parameters" = lib.mkIf failure.verifyParameters {
      description = "Verify the running kernel carries the configured ZFS parameters";
      wantedBy = ["multi-user.target"];
      after = ["aos-zfs-memory-policy.service"];
      requires = ["aos-zfs-memory-policy.service"];
      serviceConfig = {
        Type = "oneshot";
        RemainAfterExit = true;
      };
      script = lib.getExe verifyParameters;
    };

    system.checks.zfs-memory = {
      description = "Bounded ZFS memory policy checks";
      checks = [
        {
          name = "zfs-slab-geometry";
          description = "SPL allocates one object per slab";
          script = ''
            geometry = vm.succeed("cat /sys/module/spl/parameters/spl_kmem_cache_obj_per_slab").strip()
            assert geometry == "1", f"spl_kmem_cache_obj_per_slab is {geometry}"
          '';
        }
        {
          name = "zfs-arc-bounded";
          description = "The ARC ceiling is at or below the configured budget share";
          script = ''
            arc_max = int(vm.succeed("cat /sys/module/zfs/parameters/zfs_arc_max").strip())
            assert 0 < arc_max <= ${toString ceilingArcMax}, f"zfs_arc_max is {arc_max}"
          '';
        }
        {
          name = "zfs-scrub-queue-bounded";
          description = "The scrub sort queue is bounded by the budget, not by installed RAM";
          script = ''
            vm.wait_for_unit("aos-zfs-memory-policy.service")
            divisor = int(vm.succeed("cat /sys/module/zfs/parameters/zfs_scan_mem_lim_fact").strip())
            mem_total = int(vm.succeed("grep MemTotal /proc/meminfo").split()[1]) * 1024
            assert divisor >= 2, f"zfs_scan_mem_lim_fact is {divisor}"
            assert mem_total // divisor <= ${toString ceilingScrubBudget}
          '';
        }
        {
          name = "zfs-parameters-verified";
          description = "The parameter verification service accepts the running kernel";
          script = ''
            vm.wait_for_unit("aos-zfs-verify-parameters.service")
          '';
        }
        {
          name = "zfs-panics-on-oops";
          description = "A kernel oops reboots instead of wedging the storage stack";
          script = ''
            assert vm.succeed("cat /proc/sys/kernel/panic_on_oops").strip() == "1"
            assert vm.succeed("cat /proc/sys/kernel/panic").strip() == "${toString failure.panicTimeout}"
          '';
        }
      ];
    };
  };
}
