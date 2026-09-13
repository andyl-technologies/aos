##! modules/base/zfs-datasets.nix — Declared ZFS datasets and their realization
##!
##! Datasets are declared with typed properties rather than free-form strings,
##! created and converged at boot, and mounted by generated systemd mount units
##! rather than by `zfs mount -a`. Declaring them is therefore the same thing as
##! having them: a dataset that exists with the wrong properties is corrected,
##! and a mounted dataset that no configuration declares is reported.
##!
##! The property defaults encode the allocation shapes that keep ZFS from
##! stranding kernel memory. Records stay at 128 KiB unless a host opts in,
##! because a 1 MiB record turns every buffer-cache slab into a large unmovable
##! allocation. Deduplication is off and gated behind an explicit host-level
##! flag, because its table is pinned kernel memory whose size follows the
##! number of unique blocks rather than any configured limit.
{
  config,
  lib,
  pkgs,
  ...
}: let
  cfg = config.aos.filesystems.zfs;
  pool = cfg.poolName;

  # Record sizes above 128 KiB make each ZFS buffer cache slab a large,
  # unmovable allocation. Compaction cannot relocate those, so once they are
  # scattered the machine can hold hundreds of gigabytes free and still fail to
  # satisfy a higher-order request.
  smallRecordSizes = ["4K" "8K" "16K" "32K" "64K" "128K"];
  largeRecordSizes = ["256K" "512K" "1M" "2M" "4M" "8M" "16M"];

  datasetModule = {config, ...}: {
    options = {
      mountPoint = lib.mkOption {
        type = lib.types.nullOr lib.types.str;
        default = null;
        description = ''
          Absolute path where a generated systemd mount unit mounts this
          dataset. Null leaves the dataset unmounted, which is how container
          datasets and reservation-only datasets are declared.
        '';
      };

      recordSize = lib.mkOption {
        type = lib.types.enum (smallRecordSizes ++ largeRecordSizes);
        default = "128K";
        description = ''
          Logical block size for newly written data. Sizes above 128 KiB
          require `aos.filesystems.zfs.allowLargeRecords`, because they drive
          the large unmovable slab allocations that fragment physical memory.
          Changing this affects new blocks only; existing data keeps the size
          it was written with.
        '';
      };

      compression = lib.mkOption {
        type = lib.types.strMatching "[a-z0-9-]+";
        default = "zstd-3";
        description = "Compression algorithm and level for newly written data.";
      };

      atime = lib.mkOption {
        type = lib.types.bool;
        default = false;
        description = "Update access times on read, turning reads into writes.";
      };

      quota = lib.mkOption {
        type = lib.types.nullOr (lib.types.strMatching "[0-9]+[KMGTP]?");
        default = null;
        description = ''
          Hard limit on the space this dataset and its descendants may consume.
          A dataset that can grow without limit turns a local problem, such as
          a logging loop, into a pool-wide outage.
        '';
      };

      reservation = lib.mkOption {
        type = lib.types.nullOr (lib.types.strMatching "[0-9]+[KMGTP]?");
        default = null;
        description = ''
          Space reserved for this dataset regardless of other consumers
          (`refreservation`).
        '';
      };

      deduplicate = lib.mkOption {
        type = lib.types.bool;
        default = false;
        description = ''
          Deduplicate written blocks. Requires
          `aos.filesystems.zfs.allowDeduplication`. The deduplication table is
          pinned kernel memory sized by the number of unique blocks in the
          dataset, not by any configured limit, so it is the single most
          memory-hostile ZFS feature and is never enabled implicitly.
        '';
      };

      snapshot = lib.mkOption {
        type = lib.types.bool;
        default = true;
        description = ''
          Include this dataset in automatic snapshots, through the
          `com.sun:auto-snapshot` property that `aos.services.zfsAutoSnapshot`
          and compatible tools honor.
        '';
      };

      mountOptions = lib.mkOption {
        type = lib.types.listOf lib.types.str;
        default = ["nosuid" "nodev"];
        description = "Mount options for the generated systemd mount unit.";
      };

      extraProperties = lib.mkOption {
        type = lib.types.attrsOf lib.types.str;
        default = {};
        description = ''
          Additional ZFS properties applied verbatim. Use this for properties
          without a typed option here; typed options exist for the ones that
          carry memory or durability consequences.
        '';
      };
    };

    config = {
      # `legacy` hands the mount to systemd, so its ordering and dependencies
      # apply; a dataset that mounted itself would race the units expecting it.
      # Datasets with no mount point are containers or reservations and must
      # not acquire an inherited mount point from their parent.
      extraProperties.mountpoint = lib.mkDefault (
        if config.mountPoint == null
        then "none"
        else "legacy"
      );
    };
  };

  # Parents must exist before their children, both to create them and to mount
  # them. Sorting by path depth and then by name gives a stable order.
  datasetNames = builtins.attrNames cfg.datasets;
  depthOf = name: builtins.length (lib.splitString "/" name);
  orderedNames =
    lib.sort (
      left: right:
        if depthOf left != depthOf right
        then depthOf left < depthOf right
        else left < right
    )
    datasetNames;

  # ZFS property list for one declared dataset. `mountpoint` comes from
  # `extraProperties`, which the submodule sets, so systemd stays the only
  # thing that mounts a declared dataset.
  propertiesOf = name: let
    dataset = cfg.datasets.${name};
    typed =
      {
        recordsize = dataset.recordSize;
        compression = dataset.compression;
        atime =
          if dataset.atime
          then "on"
          else "off";
        dedup =
          if dataset.deduplicate
          then "on"
          else "off";
        "com.sun:auto-snapshot" =
          if dataset.snapshot
          then "true"
          else "false";
      }
      // lib.optionalAttrs (dataset.quota != null) {quota = dataset.quota;}
      // lib.optionalAttrs (dataset.reservation != null) {refreservation = dataset.reservation;};
  in
    typed // dataset.extraProperties;

  propertyArguments = name:
    lib.concatStringsSep " " (
      lib.mapAttrsToList (
        property: value: "-o ${lib.escapeShellArg "${property}=${value}"}"
      ) (propertiesOf name)
    );

  # Converge one dataset: create it with its full property set, or correct the
  # properties that drifted. Create-only properties are not reapplied; ZFS
  # rejects them and the failure would be indistinguishable from a real one.
  convergeDataset = name: let
    fullName = "${pool}/${name}";
    settable = lib.filterAttrs (property: _: !(lib.elem property createOnlyProperties)) (propertiesOf name);
  in ''
    if ! zfs list -H -o name ${lib.escapeShellArg fullName} >/dev/null 2>&1; then
      echo "aos-zfs-datasets: creating ${fullName}"
      zfs create -p ${propertyArguments name} ${lib.escapeShellArg fullName}
    else
      ${lib.concatStringsSep "\n  " (lib.mapAttrsToList (property: value: ''
      converge_property ${lib.escapeShellArg fullName} ${lib.escapeShellArg property} ${lib.escapeShellArg value}'')
    settable)}
    fi
  '';

  # Properties ZFS fixes when a dataset is created. Setting them afterwards
  # always fails, so convergence skips them rather than reporting noise.
  createOnlyProperties = ["casesensitivity" "normalization" "utf8only" "encryption" "keyformat"];

  mountedDatasets = builtins.filter (name: cfg.datasets.${name}.mountPoint != null) orderedNames;

  datasetsWithLargeRecords =
    builtins.filter (name: lib.elem cfg.datasets.${name}.recordSize largeRecordSizes) datasetNames;
  datasetsWithDeduplication =
    builtins.filter (name: cfg.datasets.${name}.deduplicate) datasetNames;

  zfsBin = lib.makeBinPath [cfg.package pkgs.coreutils pkgs.grep];

  realizeDatasets = pkgs.writeShellScriptBin "aos-zfs-datasets" ''
    set -euo pipefail

    PATH=${zfsBin}''${PATH:+:$PATH}

    # Apply one property only when it differs, so a converged host does no
    # writes and the log records real drift rather than every boot.
    converge_property() {
      dataset=$1
      property=$2
      desired=$3

      current=$(zfs get -H -o value "$property" "$dataset" 2>/dev/null || echo "")
      if [ "$current" != "$desired" ]; then
        echo "aos-zfs-datasets: $dataset $property: $current -> $desired"
        zfs set "$property=$desired" "$dataset"
      fi
    }

    ${lib.concatMapStringsSep "\n" convergeDataset orderedNames}

    ${lib.optionalString (cfg.deduplicationTableQuota != null) ''
      # Bound the deduplication table explicitly. Without a quota its size
      # follows the number of unique blocks, and every entry is pinned kernel
      # memory that the ARC budget does not cover.
      zpool set dedup_table_quota=${lib.escapeShellArg cfg.deduplicationTableQuota} ${lib.escapeShellArg pool}
    ''}

    ${lib.optionalString cfg.reservedSpace.enable ''
      # A pool with no free space cannot always be freed: deleting a file in a
      # copy-on-write filesystem is itself a write. Holding a reservation that
      # an operator can release keeps a full pool recoverable.
      reserved=${lib.escapeShellArg "${pool}/${cfg.reservedSpace.dataset}"}
      if ! zfs list -H -o name "$reserved" >/dev/null 2>&1; then
        zfs create -o mountpoint=none -o "com.sun:auto-snapshot=false" \
          -o refreservation=${lib.escapeShellArg cfg.reservedSpace.size} "$reserved"
      else
        converge_property "$reserved" refreservation ${lib.escapeShellArg cfg.reservedSpace.size}
      fi
    ''}
  '';

  # Datasets that exist and are mounted but that no configuration declares are
  # drift: nothing manages their properties, their quotas, or their snapshots.
  reportUndeclared = pkgs.writeShellScriptBin "aos-zfs-report-undeclared" ''
    set -uo pipefail

    PATH=${zfsBin}''${PATH:+:$PATH}

    declared=$(printf '%s\n' ${lib.escapeShellArgs (map (name: "${pool}/${name}") datasetNames)} \
      ${lib.optionalString cfg.reservedSpace.enable (lib.escapeShellArg "${pool}/${cfg.reservedSpace.dataset}")})

    status=0
    while read -r dataset; do
      [ -n "$dataset" ] || continue
      [ "$dataset" = ${lib.escapeShellArg pool} ] && continue
      if ! printf '%s\n' "$declared" | grep -qxF "$dataset"; then
        echo "aos-zfs-report-undeclared: $dataset exists in the pool but no configuration declares it" >&2
        status=1
      fi
    done <<< "$(zfs list -H -o name -t filesystem -r ${lib.escapeShellArg pool})"

    exit "$status"
  '';
in {
  options.aos.filesystems.zfs = {
    ## Datasets this system declares, creates, and mounts.
    datasets = lib.mkOption {
      type = lib.types.attrsOf (lib.types.submodule datasetModule);
      default = {};
      description = ''
        ZFS datasets keyed by their path below the pool. Modules contribute
        entries, `aos-zfs-datasets.service` creates and converges them at boot,
        and generated systemd mount units mount the ones that declare a mount
        point.
      '';
    };

    ## Permit record sizes above 128 KiB.
    allowLargeRecords = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = ''
        Permit datasets to declare record sizes above 128 KiB. Large records
        improve sequential throughput on archival data, and they make every
        buffer-cache slab a large unmovable allocation. Enable this only for a
        pool whose workload is sequential and whose host has memory headroom.
      '';
    };

    ## Permit datasets to enable deduplication.
    allowDeduplication = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = ''
        Permit datasets to enable deduplication. The table is pinned kernel
        memory that grows with the number of unique blocks, is not covered by
        the ARC budget, and cannot be shrunk without rewriting the data.
        Enabling this also requires `deduplicationTableQuota`.
      '';
    };

    ## Hard limit on deduplication table size.
    deduplicationTableQuota = lib.mkOption {
      type = lib.types.nullOr (lib.types.strMatching "[0-9]+[KMGTP]?");
      default = null;
      description = ''
        Pool-wide `dedup_table_quota`. Once the table reaches this size ZFS
        stops adding entries rather than continuing to consume kernel memory.
      '';
    };

    ## Space held back so a full pool stays recoverable.
    reservedSpace = {
      enable = lib.mkOption {
        type = lib.types.bool;
        default = true;
        description = ''
          Hold a reservation on an empty dataset. Freeing space in a
          copy-on-write filesystem requires writing, so a pool at capacity can
          refuse the deletes that would relieve it. An operator can release
          this reservation to recover.
        '';
      };

      dataset = lib.mkOption {
        type = lib.types.strMatching "[A-Za-z0-9_.:-]+(/[A-Za-z0-9_.:-]+)*";
        default = "reserved";
        description = "Dataset below the pool that carries the reservation.";
      };

      size = lib.mkOption {
        type = lib.types.strMatching "[0-9]+[KMGTP]?";
        default = "2G";
        description = "Reserved space held by the reservation dataset.";
      };
    };

    ## Report pool datasets that no configuration declares.
    reportUndeclaredDatasets = lib.mkOption {
      type = lib.types.bool;
      default = true;
      description = ''
        Report datasets that exist in the pool but that no configuration
        declares. Their properties, quotas, and snapshot policy are unmanaged,
        so they drift silently from the rest of the system.
      '';
    };
  };

  config = lib.mkIf cfg.enable {
    assertions = [
      {
        assertion = cfg.allowLargeRecords || datasetsWithLargeRecords == [];
        message =
          "datasets ${lib.concatStringsSep ", " datasetsWithLargeRecords} declare record sizes above 128 KiB"
          + " without aos.filesystems.zfs.allowLargeRecords; large records make each buffer-cache slab"
          + " a large unmovable allocation that fragments physical memory";
      }
      {
        assertion = cfg.allowDeduplication || datasetsWithDeduplication == [];
        message =
          "datasets ${lib.concatStringsSep ", " datasetsWithDeduplication} enable deduplication"
          + " without aos.filesystems.zfs.allowDeduplication";
      }
      {
        assertion = !cfg.allowDeduplication || cfg.deduplicationTableQuota != null;
        message =
          "aos.filesystems.zfs.allowDeduplication requires deduplicationTableQuota;"
          + " an unbounded deduplication table is pinned kernel memory outside the ZFS budget";
      }
      {
        assertion = !cfg.reservedSpace.enable || !(builtins.hasAttr cfg.reservedSpace.dataset cfg.datasets);
        message =
          "aos.filesystems.zfs.reservedSpace.dataset collides with a declared dataset;"
          + " the reservation dataset must hold no data";
      }
    ];

    # The mount helper has to be resolvable as /sbin/mount.zfs for the
    # generated mount units, which the rootfs builder arranges by linking each
    # system package's sbin entries.
    environment.systemPackages = [cfg.package];

    # The system-state datasets exist only when the pool is what carries
    # /var; a pool declared purely for data leaves the image's own /var alone.
    aos.filesystems.zfs.datasets = lib.mkIf cfg.systemState {
      "var" = {
        mountPoint = "/var";
      };
      "var/log" = {
        mountPoint = "/var/log";
        # Logs are append-heavy and latency-tolerant, and a runaway logger must
        # not be able to consume the pool the rest of the system needs.
        extraProperties.logbias = "throughput";
        quota = lib.mkDefault "8G";
      };
      "var/lib" = {
        mountPoint = "/var/lib";
      };
    };

    systemd.services."aos-zfs-datasets" = {
      description = "Create and converge declared ZFS datasets";
      wantedBy = ["local-fs.target"];
      before = ["local-fs.target"];
      after = ["zfs-import.service"];
      requires = ["zfs-import.service"];
      serviceConfig = {
        Type = "oneshot";
        RemainAfterExit = true;
      };
      # Live in-place upgrades change declared properties without a reboot.
      reloadTriggers = [realizeDatasets];
      script = lib.getExe realizeDatasets;
    };

    systemd.services."aos-zfs-report-undeclared" = lib.mkIf cfg.reportUndeclaredDatasets {
      description = "Report ZFS datasets that no configuration declares";
      wantedBy = ["multi-user.target"];
      after = ["aos-zfs-datasets.service"];
      requires = ["aos-zfs-datasets.service"];
      serviceConfig = {
        Type = "oneshot";
        RemainAfterExit = true;
      };
      script = lib.getExe reportUndeclared;
    };

    # One mount unit per declared dataset, so systemd orders them against each
    # other and against the services that need them. `zfs mount -a` would
    # instead mount whatever the pool happens to contain, in no particular
    # order and including datasets this configuration does not declare.
    systemd.mounts =
      map (name: {
        what = "${pool}/${name}";
        where = cfg.datasets.${name}.mountPoint;
        type = "zfs";
        options = lib.concatStringsSep "," cfg.datasets.${name}.mountOptions;
        wantedBy = ["local-fs.target"];
        before = ["local-fs.target"];
        after = ["aos-zfs-datasets.service"];
        requires = ["aos-zfs-datasets.service"];
      })
      mountedDatasets;

    system.checks.zfs-datasets = {
      description = "Declared ZFS dataset checks";
      checks = [
        {
          name = "zfs-datasets-realized";
          description = "Every declared dataset exists with its declared properties";
          script = ''
            vm.wait_for_unit("aos-zfs-datasets.service")
            ${lib.concatMapStringsSep "\n" (name: ''
                vm.succeed("zfs list -H -o name ${pool}/${name}")
                recordsize = vm.succeed(
                    "zfs get -H -o value recordsize ${pool}/${name}"
                ).strip()
                assert recordsize == "${cfg.datasets.${name}.recordSize}", (
                    f"${name} recordsize is {recordsize}"
                )
              '')
              orderedNames}
          '';
        }
        {
          name = "zfs-datasets-mounted";
          description = "Declared datasets are mounted at their declared mount points";
          script = ''
            mounts = vm.succeed("cat /proc/mounts")
            ${lib.concatMapStringsSep "\n" (name: ''
                assert "${pool}/${name} ${cfg.datasets.${name}.mountPoint} zfs" in mounts, (
                    "${pool}/${name} is not mounted at ${cfg.datasets.${name}.mountPoint}"
                )
              '')
              mountedDatasets}
          '';
        }
        {
          name = "zfs-records-bounded";
          description = "No dataset writes records larger than the fragmentation-safe size";
          script = ''
            sizes = vm.succeed("zfs get -H -o value -r recordsize ${pool}").split()
            oversized = [s for s in sizes if s not in ${builtins.toJSON smallRecordSizes}]
            assert oversized == ${
              if cfg.allowLargeRecords
              then "oversized"
              else "[]"
            }, f"oversized record sizes: {oversized}"
          '';
        }
        {
          name = "zfs-reserved-space";
          description = "The pool holds a reservation that keeps a full pool recoverable";
          script =
            if cfg.reservedSpace.enable
            then ''
              reservation = vm.succeed(
                  "zfs get -H -o value refreservation ${pool}/${cfg.reservedSpace.dataset}"
              ).strip()
              assert reservation != "none", "reservation dataset holds no reservation"
            ''
            else ''
              pass
            '';
        }
      ];
    };
  };
}
