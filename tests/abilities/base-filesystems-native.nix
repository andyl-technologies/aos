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
in
  assert initrd.deployment.graph.nodes == {};
  assert device.input.kind == "block";
  assert mapping.dependencies == [(fixture.identity device)];
  assert format.dependencies == [(fixture.identity mapping)];
  assert swap.dependencies == [(fixture.identity format)];
  assert mapping.input.cipher == "aes-xts-plain64";
  assert mapping.input.keySizeBits == 256;
  assert format.input.policy == "always";
  assert swap.handler.executable == "${fixture.manager}/bin/aos-systemd-native-resources";
  assert builtins.elem (fixture.identity pool) dataset.dependencies;
  assert dataset.input.mountpoint == "/var/lib/data";
  assert zfs.config.aos.kernel.externalPackages.aos-zfs-provider != [];
  assert builtins.all (entry: entry.assertion) zfs.config.assertions; true
