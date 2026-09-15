##! Checks encrypted swap composition through native block-storage resources.
{
  lib,
  pkgs,
}: let
  evaluate = import ./base-module-evaluation.nix {inherit lib pkgs;};
  evaluated = evaluate {
    name = "base-filesystems";
    module = ../../modules/base/filesystems.nix;
    packages = [
      pkgs.systemd
      pkgs.cryptsetup
      pkgs.aos-cryptsetup-provider
      pkgs.aos-storage-format-provider
      pkgs.aos-zfs-provider
    ];
    extraModules = [{
      aos.filesystems.zfs = {
        enable = true;
        systemState = false;
        datasets."srv/data" = {
          mountPoint = "/srv/data";
          quota = "16G";
          compression = "zstd-7";
        };
      };
    }];
  };
  config = evaluated.config;
  requests = config.aos.abilities.requests;
  resultOf = request: output: {
    _type = "aos-request-output-reference";
    inherit request output;
  };
in
  assert requests."cryptsetup:swap-device".parameters.device == "/dev/disk/by-partlabel/swap";
  assert requests."cryptsetup:encrypted-swap-mapping".parameters.source
  == resultOf "cryptsetup:swap-device" "device-node";
  assert requests."cryptsetup:encrypted-swap-format".parameters.policy == "always";
  assert requests."cryptsetup:encrypted-swap-format".parameters.source
  == resultOf "cryptsetup:encrypted-swap-mapping" "mapped-device";
  assert requests."cryptsetup:encrypted-swap".parameters.source
  == resultOf "cryptsetup:encrypted-swap-format" "formatted-path";
  assert !(config.systemd.services ? cryptswap);
  assert requests ? "aos-zfs-provider:pool";
  assert requests ? "aos-zfs-provider:dataset-${builtins.substring 0 32 (builtins.hashString "sha256" "srv/data")}";
  assert requests."aos-zfs-provider:dataset-${builtins.substring 0 32 (builtins.hashString "sha256" "srv/data")}".parameters.properties.quota == "16G";
  assert lib.hasInfix "/dev/disk/by-partlabel/var  /var  ext4" config.environment.etc.fstab.text;
  assert !(config.systemd.services ? "zfs-import");
  assert !(config.systemd.services ? "zfs-mount"); true
