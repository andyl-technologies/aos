##! Package-owned MD assembly and state-backed data-volume mounts.
##!
##! Array creation, formatting, and marker commitment belong to the native
##! provisioning transaction. The initrd service only assembles existing arrays;
##! host mounts consume the same validated logical partition and array names.
{
  config,
  package,
  lib,
  ...
}: let
  cfg = config.aos.filesystems.volumes;
  storage = config.aos.provisioning.storage;

  # A pool that carries /var owns the whole system-state path; the md layer
  # is then never part of the boot-time storage chain.
  zfsState = config.aos.boot.storage.backend == "zfs-zvol";
  hostStage = config.aos.boot.stage == "host";
  initrdStage = config.aos.boot.stage == "initrd";
  mounts = config.aos.abilities.mount.operations.ensure.effects;

  volumeType = lib.types.submodule {
    options = {
      mountPoint = lib.mkOption {
        type = lib.types.strMatching "/.*";
        description = ''
          Absolute mount point for the volume, beneath `/srv` or `/var`.
          The image root is read-only, so a mount point can only be created
          under a writable tree: `/srv` is a persistent bind of `/var/srv`
          that every host provides for data volumes.
        '';
      };

      mountOptions = lib.mkOption {
        type = lib.types.listOf lib.types.str;
        default = ["nosuid" "nodev"];
        description = "Mount options passed to the generated mount unit.";
      };
    };
  };

  # The filesystem label a volume name resolves to: an array carries its own
  # name, a partition carries its GPT label.
  volumeLabel = name:
    if storage.arrays ? ${name}
    then name
    else storage.partitions.${name}.label;

  volumeExists = name: storage.arrays ? ${name} || storage.partitions ? ${name};

  # Partitions that are array members never carry a mountable filesystem.
  memberPartitions = lib.concatMap (array: array.members) (builtins.attrValues storage.arrays);

  volumeHasFilesystem = name:
    if storage.arrays ? ${name}
    then storage.arrays.${name}.format != null
    else
      !(builtins.elem name memberPartitions)
      && builtins.elem storage.partitions.${name}.format ["ext4" "xfs" "vfat"];

  volumeFsType = name:
    if storage.arrays ? ${name}
    then storage.arrays.${name}.format
    else storage.partitions.${name}.format;

  # mkfs.ext4 truncates longer labels and mkfs.xfs rejects them; either way
  # the mount identity would point at nothing.
  labelLimit = name:
    if volumeFsType name == "xfs"
    then 12
    else 16;

  mountedVolumes = builtins.attrNames cfg;

  # The image root is read-only and cannot know host.nix mount points, so a
  # volume may only mount under a tree that is writable by the time
  # local-fs.target assembles: /srv (a bind of the persistent /var/srv, see
  # below) or /var itself.
  writableRoots = ["/srv/" "/var/"];
  mountPointIsWritable = name:
    builtins.any (root: lib.hasPrefix root cfg.${name}.mountPoint) writableRoots;
in {
  options.aos.filesystems.volumes = lib.mkOption {
    type = lib.types.attrsOf volumeType;
    default = {};
    description = ''
      Mount units for data volumes declared in `aos.provisioning.storage`,
      keyed by the logical partition or array name. The system-state volume
      `var` is mounted by the initrd and must not be listed here. A volume
      that is TPM-sealed is unavailable until the first Secure Boot enforcing
      boot has sealed it; its mount unit is wanted rather than required by
      `local-fs.target`, so an absent volume degrades the host without
      blocking boot.
    '';
  };

  config = lib.mkMerge [
    {
      assertions =
        [
          {
            assertion = !(cfg ? var);
            message = "aos.filesystems.volumes must not declare 'var'; the initrd mounts the system-state volume.";
          }
        ]
        ++ map (name: {
          assertion = volumeExists name;
          message = "aos.filesystems.volumes.${name} names no aos.provisioning.storage partition or array.";
        })
        mountedVolumes
        ++ map (name: {
          assertion = mountPointIsWritable name;
          message = "aos.filesystems.volumes.${name}.mountPoint must lie under /srv or /var; the image root is read-only and cannot hold '${cfg.${name}.mountPoint}'.";
        })
        mountedVolumes
        ++ map (name: {
          assertion = !(volumeExists name) || volumeHasFilesystem name;
          message = "aos.filesystems.volumes.${name} refers to a raw partition, an array member, or a raw array; only a formatted volume can be mounted.";
        })
        mountedVolumes
        ++ map (name: {
          assertion = !(volumeExists name && volumeHasFilesystem name) || builtins.stringLength (volumeLabel name) <= labelLimit name;
          message = "aos.filesystems.volumes.${name}: filesystem label '${volumeLabel name}' exceeds the ${toString (labelLimit name)}-byte ${toString (volumeFsType name)} label limit; shorten the partition label.";
        })
        mountedVolumes;
    }
    (lib.mkIf (hostStage && !zfsState) {
      # The state-backed /srv root is established before any nested volume.
      aos.abilities.mount.operations.ensure.effects =
        {
          storage-srv = {
            input = {
              name = "storage-srv";
              source = "/var/srv";
              destination = "/srv";
              options = ["bind"];
            };
          };
        }
        // builtins.listToAttrs (map (name: {
            name = "storage-volume-${name}";
            value = {
              after = [mounts.storage-srv.outputs.resource];
              input = {
                name = "storage-volume-${name}";
                source = "/dev/disk/by-label/${volumeLabel name}";
                destination = cfg.${name}.mountPoint;
                filesystem = volumeFsType name;
                # Preserve boot degradation for a sealed volume not yet available.
                optional = true;
                options = cfg.${name}.mountOptions;
              };
            };
          })
          mountedVolumes);
    })
    (lib.mkIf (initrdStage && !zfsState) {
      aos.services.storage-topology = {
        enable = true;
        autoStart = false;
        activationOwner = "image";
        service = "aos-storage-topology";
        manager_identity = {
          name = "aos-storage-topology";
          aliases = [];
        };
        lifecycle = {
          description = "Assemble committed Linux MD storage arrays";
          execution_model = "oneshot";
          environment_files = [];
          condition = [];
          pre_start = [];
          start = [
            {
              executable = {
                path = "${package}/bin/aos-storage-topology";
                arguments = [];
              };
              ignore_failure = false;
            }
          ];
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
        readiness = {
          mechanism = "successful-exit";
          signal_scope = "none";
          timeout_millis = 90000;
        };
        dependencies = {
          prerequisites = [];
          after = ["aos-ability-initrd-controller.service" "systemd-udev-settle.service"];
          before = ["mount-var.service" "aos-var-crypt.service" "initrd-root-fs.target" "systemd-veritysetup@root.service" "aos-verity-root-verify.service"];
          requires = ["aos-ability-initrd-controller.service"];
          wants = [];
          requisite = [];
          conflicts = [];
          binds_to = [];
          part_of = [];
          upholds = [];
          required_by = ["initrd-root-fs.target"];
          wanted_by = [];
          required_mounts = [];
          implicit_dependencies = false;
        };
      };
    })
  ];
}
