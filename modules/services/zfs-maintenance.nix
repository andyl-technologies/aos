##! modules/services/zfs-maintenance.nix — Pool lifecycle, health, and telemetry
##!
##! A pool needs more than an installer. Without the event daemon a failing
##! vdev produces no action at all: no hot spare, no fault marking, no log
##! entry an operator would notice. Without scheduled scrubs, checksum errors
##! are found when data is read rather than while redundancy can still repair
##! them. Without trim, a flash pool degrades under its own stale blocks.
##!
##! The telemetry here is deliberately specific. Free memory and pool capacity
##! look healthy right up to the failure, so this module exports the quantities
##! that actually move first: the ARC's size against its target, how much of its
##! metadata is pinned rather than evictable, and how many high-order free
##! blocks the buddy allocator still has per NUMA node. A host that is heading
##! for allocation stalls shows it in those series days before free memory
##! reflects it.
{
  config,
  lib,
  pkgs,
  ...
}: let
  cfg = config.aos.services.zfsMaintenance;
  zfs = config.aos.filesystems.zfs;
  pool = zfs.poolName;

  # OpenZFS installs zpool and zfs into sbin rather than bin; both paths are
  # needed or the health and metric scripts find no ZFS commands at all.
  tools = [zfs.package pkgs.coreutils pkgs.gawk pkgs.grep];
  toolPath = lib.concatStringsSep ":" [
    (lib.makeBinPath tools)
    (lib.makeSearchPath "sbin" tools)
  ];

  # `zpool status -x` prints a single healthy line and exits zero even when a
  # vdev is degraded, so health is read from the pool's own state property.
  healthCheck = ''
    set -uo pipefail

    PATH=${toolPath}''${PATH:+:$PATH}

    state=$(zpool list -H -o health ${lib.escapeShellArg pool} 2>/dev/null || echo UNKNOWN)
    errors=$(zpool status -x ${lib.escapeShellArg pool} 2>&1 || true)

    case "$state" in
      ONLINE)
        ;;
      *)
        echo "aos-zfs-health: pool ${pool} is $state" >&2
        echo "$errors" >&2
        exit 1
        ;;
    esac

    # Read, write, and checksum counters are cumulative. A non-zero value means
    # a device returned bad data at some point, which deserves attention even
    # while the pool still reports itself online. Rows are identified by their
    # vdev state column so the table header is not mistaken for a device.
    faults=$(zpool status -p ${lib.escapeShellArg pool} | awk '
      $2 ~ /^(ONLINE|DEGRADED|FAULTED|OFFLINE|UNAVAIL|REMOVED)$/ {
        errors += $3 + $4 + $5
      }
      END { print errors + 0 }
    ')
    if [ "$faults" -gt 0 ]; then
      echo "aos-zfs-health: pool ${pool} is online with $faults accumulated device errors" >&2
      echo "$errors" >&2
      exit 1
    fi

    # An unpinned pool enables every feature of whichever release last touched
    # it. On an A/B image that silently removes the rollback slot's ability to
    # import the pool, which is the one thing rollback exists to preserve.
    # Nothing here ever runs `zpool upgrade`; enabling a feature is an operator
    # decision made once every slot can read it.
    compatibility=$(zpool get -H -o value compatibility ${lib.escapeShellArg pool} 2>/dev/null || echo off)
    case "$compatibility" in
      off|"-"|"")
        echo "aos-zfs-health: pool ${pool} pins no feature set (compatibility=$compatibility);" \
          "an older image slot may be unable to import it after a rollback" >&2
        exit 1
        ;;
    esac
  '';

  # Prometheus textfile format. Every series here is a leading indicator: they
  # move while the host still reports ample free memory and a healthy pool.
  metricsSnapshot = ''
    set -euo pipefail

    PATH=${toolPath}''${PATH:+:$PATH}

    destination=${lib.escapeShellArg cfg.metrics.path}
    staging="$destination.tmp"
    mkdir -p "$(dirname "$destination")"

    {
      echo "# HELP aos_zfs_arc_bytes Current ARC size in bytes."
      echo "# TYPE aos_zfs_arc_bytes gauge"
      echo "# HELP aos_zfs_arc_target_bytes ARC target size in bytes."
      echo "# TYPE aos_zfs_arc_target_bytes gauge"
      echo "# HELP aos_zfs_arc_metadata_bytes ARC metadata by evictability."
      echo "# TYPE aos_zfs_arc_metadata_bytes gauge"
      echo "# HELP aos_zfs_arc_evict_skip_total Eviction candidates skipped."
      echo "# TYPE aos_zfs_arc_evict_skip_total counter"

      # An ARC above its target, or metadata that is largely non-evictable,
      # is the state in which reclaim scans millions of candidates and frees
      # nothing. Both are invisible in free-memory accounting.
      awk '
        $1 == "size"                    { size = $3 }
        $1 == "c"                       { target = $3 }
        $1 == "mru_metadata"            { mru = $3 }
        $1 == "mru_evictable_metadata"  { mru_evictable = $3 }
        $1 == "mfu_metadata"            { mfu = $3 }
        $1 == "mfu_evictable_metadata"  { mfu_evictable = $3 }
        $1 == "evict_skip"              { skip = $3 }
        END {
          evictable = mru_evictable + mfu_evictable
          pinned = (mru + mfu) - evictable
          printf "aos_zfs_arc_bytes %d\n", size
          printf "aos_zfs_arc_target_bytes %d\n", target
          printf "aos_zfs_arc_metadata_bytes{state=\"evictable\"} %d\n", evictable
          printf "aos_zfs_arc_metadata_bytes{state=\"pinned\"} %d\n", pinned
          printf "aos_zfs_arc_evict_skip_total %d\n", skip
        }
      ' /proc/spl/kstat/zfs/arcstats

      echo "# HELP aos_memory_free_blocks Free buddy-allocator blocks by order and NUMA node."
      echo "# TYPE aos_memory_free_blocks gauge"

      # Higher orders reaching zero while the host still shows hundreds of
      # gigabytes free is the signature of unmovable-allocation fragmentation.
      awk '
        /^Node/ {
          node = $2
          sub(",", "", node)
          zone = $4
          for (order = 0; order <= NF - 5; order++) {
            printf "aos_memory_free_blocks{node=\"%s\",zone=\"%s\",order=\"%d\"} %d\n", \
              node, zone, order, $(order + 5)
          }
        }
      ' /proc/buddyinfo

      echo "# HELP aos_memory_node_bytes Per-NUMA-node memory by state."
      echo "# TYPE aos_memory_node_bytes gauge"

      for meminfo in /sys/devices/system/node/node*/meminfo; do
        [ -r "$meminfo" ] || continue
        awk '
          $3 == "MemFree:"    { printf "aos_memory_node_bytes{node=\"%s\",state=\"free\"} %d\n", $2, $4 * 1024 }
          $3 == "SUnreclaim:" { printf "aos_memory_node_bytes{node=\"%s\",state=\"unreclaimable_slab\"} %d\n", $2, $4 * 1024 }
        ' "$meminfo"
      done

      echo "# HELP aos_memory_compaction_total Kernel compaction attempts by outcome."
      echo "# TYPE aos_memory_compaction_total counter"
      awk '
        $1 == "compact_stall"   { printf "aos_memory_compaction_total{outcome=\"stall\"} %d\n", $2 }
        $1 == "compact_fail"    { printf "aos_memory_compaction_total{outcome=\"fail\"} %d\n", $2 }
        $1 == "compact_success" { printf "aos_memory_compaction_total{outcome=\"success\"} %d\n", $2 }
      ' /proc/vmstat

      echo "# HELP aos_zfs_pool_health Pool health, 1 when online."
      echo "# TYPE aos_zfs_pool_health gauge"
      state=$(zpool list -H -o health ${lib.escapeShellArg pool} 2>/dev/null || echo UNKNOWN)
      if [ "$state" = ONLINE ]; then
        printf 'aos_zfs_pool_health{pool="%s",state="%s"} 1\n' ${lib.escapeShellArg pool} "$state"
      else
        printf 'aos_zfs_pool_health{pool="%s",state="%s"} 0\n' ${lib.escapeShellArg pool} "$state"
      fi

      echo "# HELP aos_zfs_pool_fragmentation_ratio Free-space fragmentation, 0 to 1."
      echo "# TYPE aos_zfs_pool_fragmentation_ratio gauge"
      fragmentation=$(zpool list -H -o fragmentation ${lib.escapeShellArg pool} 2>/dev/null | tr -d '%')
      case "$fragmentation" in
        ""|*[!0-9]*) ;;
        *) printf 'aos_zfs_pool_fragmentation_ratio{pool="%s"} %s\n' \
             ${lib.escapeShellArg pool} "$(awk -v value="$fragmentation" 'BEGIN { print value / 100 }')" ;;
      esac
    } > "$staging"

    # Collectors read this path on their own schedule, so publish atomically
    # rather than letting a scrape catch a half-written file.
    mv "$staging" "$destination"
  '';

  zedConfiguration = ''
    # zed.rc — generated by modules/services/zfs-maintenance.nix
    # Do not edit manually.

    # Log every event to syslog so vdev faults reach the journal rather than
    # only the pool's own event ring, which is lost on reboot.
    ZED_SYSLOG_PRIORITY="daemon.notice"
    ZED_SYSLOG_TAG="zed"

    # Take a failing device out of service rather than continuing to issue I/O
    # to it. Redundant pools keep serving from their remaining members.
    ZED_USE_ENCLOSURE_LEDS="1"
    ZED_SCRUB_AFTER_RESILVER="${
      if cfg.scrubAfterResilver
      then "1"
      else "0"
    }"
  '';
in {
  options.aos.services.zfsMaintenance = {
    enable = lib.mkOption {
      type = lib.types.bool;
      default = config.aos.filesystems.zfs.enable;
      defaultText = "aos.filesystems.zfs.enable";
      description = ''
        Run the pool lifecycle services: the event daemon, scheduled scrubs and
        trims, health checks, and memory-pressure telemetry.
      '';
    };

    ## Respond to pool events, including device faults and resilver completion.
    eventDaemon = lib.mkOption {
      type = lib.types.bool;
      default = true;
      description = ''
        Run the ZFS Event Daemon. Without it a failing device produces no
        action: no fault marking, no hot-spare activation, and no operator
        notification beyond the pool's own event ring, which does not survive
        a reboot.
      '';
    };

    ## Start a scrub once a resilver completes.
    scrubAfterResilver = lib.mkOption {
      type = lib.types.bool;
      default = true;
      description = ''
        Scrub after a resilver finishes. A resilver only rebuilds the replaced
        device, so a scrub is what confirms the rest of the pool survived
        whatever took the device out.
      '';
    };

    scrub = {
      enable = lib.mkOption {
        type = lib.types.bool;
        default = true;
        description = ''
          Verify every block against its checksum on a schedule, so latent
          corruption is found while redundancy can still repair it rather than
          when an application reads the block.
        '';
      };

      calendar = lib.mkOption {
        type = lib.types.str;
        default = "monthly";
        description = "systemd calendar expression for scheduled scrubs.";
      };
    };

    trim = {
      enable = lib.mkOption {
        type = lib.types.bool;
        default = true;
        description = ''
          Tell flash devices which blocks the pool no longer uses. Without it
          a device's own allocator degrades as its spare area fills with data
          the pool has already freed.
        '';
      };

      calendar = lib.mkOption {
        type = lib.types.str;
        default = "weekly";
        description = "systemd calendar expression for scheduled trims.";
      };
    };

    healthCheck = {
      enable = lib.mkOption {
        type = lib.types.bool;
        default = true;
        description = ''
          Check pool state and accumulated device errors on a schedule, failing
          the unit so a degraded pool appears in `systemctl --failed`.
        '';
      };

      calendar = lib.mkOption {
        type = lib.types.str;
        default = "*:0/15";
        description = "systemd calendar expression for pool health checks.";
      };
    };

    metrics = {
      enable = lib.mkOption {
        type = lib.types.bool;
        default = true;
        description = ''
          Publish ARC, fragmentation, and per-NUMA-node memory metrics in
          Prometheus text format. These move well before free memory or pool
          capacity reflect a problem, so they are what an alert should watch.
        '';
      };

      calendar = lib.mkOption {
        type = lib.types.str;
        default = "*:0/1";
        description = "systemd calendar expression for metric snapshots.";
      };

      path = lib.mkOption {
        type = lib.types.strMatching "/.*";
        default = "/var/lib/aos-metrics/zfs.prom";
        description = ''
          File the snapshot is published to, in the textfile-collector format
          that Prometheus collectors read.
        '';
      };
    };

    randomizedDelay = lib.mkOption {
      type = lib.types.str;
      default = "10m";
      description = ''
        Maximum randomized delay applied to scheduled maintenance, so a fleet
        does not scrub in lockstep.
      '';
    };
  };

  config = lib.mkIf (cfg.enable && zfs.enable) {
    assertions = [
      {
        assertion = zfs.enable;
        message = "aos.services.zfsMaintenance requires aos.filesystems.zfs.enable";
      }
    ];

    environment.etc."zfs/zed.rc" = lib.mkIf cfg.eventDaemon {
      text = zedConfiguration;
    };

    systemd.services = lib.mkMerge [
      (lib.mkIf cfg.eventDaemon {
        "zfs-zed" = {
          description = "ZFS Event Daemon";
          wantedBy = ["multi-user.target"];
          after = ["zfs-import.service"];
          requires = ["zfs-import.service"];
          # zed does not signal readiness, so it is a plain foreground daemon
          # (`-F`) as upstream runs it. Losing the listener means losing every
          # subsequent device fault, so it restarts unconditionally.
          unitConfig.ConditionPathIsDirectory = "/sys/module/zfs";
          # zed requires its configuration beside its hooks. Assemble that
          # directory in /run so frozen host evaluation only retains inputs.
          preStart = ''
            ${pkgs.coreutils}/bin/rm -rf /run/aos-zed.d
            ${pkgs.coreutils}/bin/mkdir -p /run/aos-zed.d
            ${pkgs.coreutils}/bin/cp -a ${zfs.package}/etc/zfs/zed.d/. /run/aos-zed.d/
            ${pkgs.coreutils}/bin/cp /etc/zfs/zed.rc /run/aos-zed.d/zed.rc
          '';
          serviceConfig = {
            Type = "simple";
            ExecStart = "${zfs.package}/sbin/zed -F -d /run/aos-zed.d";
            Restart = "always";
            RestartSec = "5s";
            StateDirectory = "zed";
          };
        };
      })

      (lib.mkIf cfg.scrub.enable {
        "aos-zfs-scrub" = {
          description = "Scrub ZFS pool ${pool}";
          after = ["zfs-import.service"];
          requires = ["zfs-import.service"];
          serviceConfig = {
            Type = "oneshot";
            # A scrub competes with real work for both I/O and the sort-queue
            # memory the ZFS budget allows, so it yields to everything else.
            Nice = 19;
            IOSchedulingClass = "idle";
            # `zpool scrub` returns as soon as the scan starts; the pool
            # reports progress and the health check observes the outcome.
            ExecStart = "${zfs.package}/sbin/zpool scrub ${pool}";
          };
        };
      })

      (lib.mkIf cfg.trim.enable {
        "aos-zfs-trim" = {
          description = "Trim ZFS pool ${pool}";
          after = ["zfs-import.service"];
          requires = ["zfs-import.service"];
          serviceConfig = {
            Type = "oneshot";
            Nice = 19;
            IOSchedulingClass = "idle";
            ExecStart = "${zfs.package}/sbin/zpool trim ${pool}";
            # A pool on devices without discard support rejects the request;
            # that is a property of the hardware, not a failure to report.
            SuccessExitStatus = "0 1";
          };
        };
      })

      (lib.mkIf cfg.healthCheck.enable {
        "aos-zfs-health" = {
          description = "Check ZFS pool ${pool} health";
          after = ["zfs-import.service"];
          requires = ["zfs-import.service"];
          serviceConfig = {
            Type = "oneshot";
          };
          script = healthCheck;
        };
      })

      (lib.mkIf cfg.metrics.enable {
        "aos-zfs-metrics" = {
          description = "Publish ZFS and memory-pressure metrics";
          after = ["zfs-import.service"];
          requires = ["zfs-import.service"];
          serviceConfig = {
            Type = "oneshot";
            Nice = 19;
          };
          script = metricsSnapshot;
        };
      })
    ];

    systemd.timers = lib.mkMerge [
      (lib.mkIf cfg.scrub.enable {
        "aos-zfs-scrub" = {
          description = "Schedule ZFS pool scrubs";
          wantedBy = ["timers.target"];
          timerConfig = {
            OnCalendar = cfg.scrub.calendar;
            Persistent = true;
            RandomizedDelaySec = cfg.randomizedDelay;
            Unit = "aos-zfs-scrub.service";
          };
        };
      })

      (lib.mkIf cfg.trim.enable {
        "aos-zfs-trim" = {
          description = "Schedule ZFS pool trims";
          wantedBy = ["timers.target"];
          timerConfig = {
            OnCalendar = cfg.trim.calendar;
            Persistent = true;
            RandomizedDelaySec = cfg.randomizedDelay;
            Unit = "aos-zfs-trim.service";
          };
        };
      })

      (lib.mkIf cfg.healthCheck.enable {
        "aos-zfs-health" = {
          description = "Schedule ZFS pool health checks";
          wantedBy = ["timers.target"];
          timerConfig = {
            OnCalendar = cfg.healthCheck.calendar;
            Persistent = true;
            Unit = "aos-zfs-health.service";
          };
        };
      })

      (lib.mkIf cfg.metrics.enable {
        "aos-zfs-metrics" = {
          description = "Schedule ZFS metric snapshots";
          wantedBy = ["timers.target"];
          timerConfig = {
            OnCalendar = cfg.metrics.calendar;
            Persistent = false;
            Unit = "aos-zfs-metrics.service";
          };
        };
      })
    ];

    system.checks.zfs-maintenance = {
      description = "ZFS pool lifecycle checks";
      checks =
        [
          {
            name = "zfs-pool-healthy";
            description = "The pool reports itself online with no device errors";
            script = ''
              vm.succeed("systemctl start aos-zfs-health.service")
            '';
          }
        ]
        ++ lib.optional cfg.eventDaemon {
          name = "zfs-event-daemon-running";
          description = "The event daemon is running to act on device faults";
          script = ''
            vm.wait_for_unit("zfs-zed.service")
          '';
        }
        ++ lib.optional cfg.metrics.enable {
          name = "zfs-metrics-published";
          description = "Metrics expose ARC pinning and high-order free blocks";
          script = ''
            vm.succeed("systemctl start aos-zfs-metrics.service")
            metrics = vm.succeed("cat ${cfg.metrics.path}")
            for series in (
                "aos_zfs_arc_bytes",
                "aos_zfs_arc_target_bytes",
                'aos_zfs_arc_metadata_bytes{state="pinned"}',
                "aos_memory_free_blocks",
                "aos_zfs_pool_health",
            ):
                assert series in metrics, f"{series} missing from ${cfg.metrics.path}"
          '';
        }
        ++ [
          {
            name = "zfs-pool-features-pinned";
            description = "The pool pins a feature set so an older slot can still import it";
            script = ''
              compatibility = vm.succeed(
                  "zpool get -H -o value compatibility ${pool}"
              ).strip()
              assert compatibility not in ("off", "-", ""), (
                  f"pool feature set is unpinned: {compatibility}"
              )
            '';
          }
        ]
        ++ lib.optional cfg.scrub.enable {
          name = "zfs-scrub-scheduled";
          description = "Scrubs are scheduled so latent corruption is found by ZFS";
          script = ''
            vm.succeed("systemctl is-active aos-zfs-scrub.timer")
          '';
        }
        ++ lib.optional cfg.scrub.enable {
          name = "zfs-scrub-completes";
          description = "A scrub runs to completion and repairs nothing on a healthy pool";
          # Exercises the scan path with the bounded sort queue in force, which
          # is the parameter most likely to make a scrub misbehave.
          script = ''
            vm.succeed("systemctl start aos-zfs-scrub.service")
            vm.wait_until_succeeds(
                "zpool status ${pool} | grep -q 'scan: scrub repaired'", timeout=120
            )

            status = vm.succeed("zpool status ${pool}")
            assert "with 0 errors" in status, status
            assert "repaired 0B" in status, status
          '';
        }
        ++ lib.optional cfg.metrics.enable {
          name = "zfs-metrics-track-arc";
          description = "Published ARC figures match what the kernel reports";
          script = ''
            vm.succeed("systemctl start aos-zfs-metrics.service")
            metrics = vm.succeed("cat ${cfg.metrics.path}")

            # Values are parsed as floats because the fragmentation ratio is
            # fractional; the counters compare equal to their integer values.
            published = {
                line.split()[0]: float(line.split()[1])
                for line in metrics.splitlines()
                if line and not line.startswith("#") and " " in line
            }
            target = int(
                vm.succeed("awk '$1 == \"c\" { print $3 }' /proc/spl/kstat/zfs/arcstats").strip()
            )
            assert published["aos_zfs_arc_target_bytes"] == target, (
                f"published target {published['aos_zfs_arc_target_bytes']} != kernel {target}"
            )
            assert published["aos_zfs_arc_bytes"] > 0
            assert published['aos_zfs_pool_health{pool="${pool}",state="ONLINE"}'] == 1
          '';
        };
    };
  };
}
