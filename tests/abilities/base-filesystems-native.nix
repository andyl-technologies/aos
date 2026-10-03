##! Native encrypted swap and ZFS retain the full storage dependency chain.
{
  lib,
  pkgs,
}: let
  fixture = import ./_native-storage-evaluation.nix {inherit lib;};
  encrypted = fixture.evaluate {packages = [fixture.crypto];};
  initrd = fixture.evaluate {
    packages = [fixture.crypto];
    modules = [
      {
        options.aos.boot.stage = lib.mkOption {
          type = lib.types.enum ["host" "initrd"];
          default = "initrd";
        };
      }
    ];
  };
  device = fixture.only encrypted "present";
  mapping = fixture.only encrypted "open";
  format = fixture.only encrypted "format";
  swap = fixture.only encrypted "ensure";
  zfs = fixture.evaluate {
    packages = [fixture.zfsProvider];
    modules = [
      {
        aos.filesystems.zfs = {
          enable = true;
          systemState = false;
          datasets.data.mountPoint = "/var/lib/data";
        };
      }
    ];
  };
  pool = fixture.only zfs "import";
  dataset = fixture.only zfs "mount";
  reportKey = "zfs-storage.aos-zfs-report-undeclared";
  reportOf = evaluated: builtins.head (builtins.filter (node: builtins.elem reportKey node.identity) (fixture.find evaluated "realize"));
  report = reportOf zfs;
  reportArguments = evaluated: (builtins.head (reportOf evaluated).input.lifecycle.start).executable.arguments;
  zfsWith = settings:
    fixture.evaluate {
      packages = [fixture.zfsProvider];
      modules = [
        {
          aos.filesystems.zfs =
            {
              enable = true;
              systemState = false;
              datasets.data.mountPoint = "/var/lib/data";
            }
            // settings;
        }
      ];
    };
  withoutReservation = zfsWith {reservedSpace.enable = false;};
  withoutReport = zfsWith {reportUndeclaredDatasets = false;};
  disabledZfs = zfsWith {enable = false;};
  hasReport = evaluated: builtins.any (node: builtins.elem reportKey node.identity) (fixture.find evaluated "realize");
  withActivator = fixture.evaluate {
    packages = [fixture.zfsProvider];
    modules = [
      ({config, ...}: {
        options.aos.boot.hostActivatorService = lib.mkOption {
          type = lib.types.nullOr lib.types.str;
          default = "selected-activator";
        };
        config = {
          aos.filesystems.zfs = {
            enable = true;
            systemState = false;
            datasets.data.mountPoint = "/var/lib/data";
          };
          aos.services.selected-activator = {
            enable = true;
            manager_identity = {
              name = "actual-host-activator";
              aliases = [];
            };
            lifecycle = config.aos.services.${reportKey}.lifecycle;
          };
        };
      })
    ];
  };
in
  assert initrd.deployment.graph.nodes == {};
  assert device.input.kind == "block";
  assert mapping.dependencies == [(fixture.identity device)];
  assert format.dependencies == [(fixture.identity mapping)];
  assert swap.dependencies == [(fixture.identity format)];
  assert mapping.input.cipher == "aes-xts-plain64";
  assert mapping.input.keySizeBits == 256;
  assert format.input.policy == "always";
  assert swap.handler.executable == "${fixture.manager.handlers}/bin/aos-systemd-native-resources";
  assert builtins.elem (fixture.identity pool) dataset.dependencies;
  assert zfs.config.aos.filesystems.zfs.poolName == "rpool";
  assert pool.input.pool == "rpool";
  assert dataset.input.mountpoint == "/var/lib/data";
  assert builtins.attrNames zfs.config.aos.abilities.zfsDataset.operations.mount.effects == ["data" "reserved"];
  assert builtins.all (node: builtins.elem (fixture.identity node) report.dependencies) ([pool] ++ fixture.find zfs "mount");
  assert report.input.activation_owner == "ability" && report.input.auto_start;
  assert report.input.lifecycle.execution_model == "oneshot" && report.input.lifecycle.start_mode == "enqueue";
  assert report.input.dependencies.wanted_by == ["multi-user.target"];
  assert report.input.dependencies.after == [];
  assert (reportOf withActivator).input.dependencies.after == ["actual-host-activator"];
  assert builtins.head (reportArguments zfs) == "report-undeclared";
  assert lib.drop 2 (reportArguments zfs) == ["rpool" "rpool/data" "rpool/reserved"];
  assert lib.drop 2 (reportArguments withoutReservation) == ["rpool" "rpool/data"];
  assert !(hasReport withoutReport) && !(hasReport disabledZfs);
  assert fixture.find withoutReport "import" != [] && fixture.find withoutReport "mount" != [];
  assert disabledZfs.deployment.graph.nodes == {};
  assert zfs.config.aos.kernel.externalPackages.aos-zfs-provider != [];
  assert builtins.all (entry: entry.assertion) zfs.config.assertions; true
