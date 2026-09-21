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
    extraModules = [
      {
        aos.filesystems.zfs = {
          enable = true;
          systemState = false;
          datasets."srv/data" = {
            mountPoint = "/srv/data";
            quota = "16G";
            compression = "zstd-7";
          };
        };
      }
    ];
  };
  systemState = evaluate {
    name = "base-filesystems-system-state";
    module = ../../modules/base/filesystems.nix;
    packages = [
      pkgs.systemd
      pkgs.aos-zfs-provider
    ];
    extraModules = [
      {
        aos.boot.storage.backend = "zfs-zvol";
        aos.filesystems.zfs = {
          enable = true;
          systemState = true;
          reservedSpace.enable = false;
        };
      }
    ];
  };
  kernelIntegration = evaluate {
    name = "base-kernel-package-contributions";
    module = ../../modules/base/kernel.nix;
    packages = [
      pkgs.systemd
      pkgs.aos-zfs-provider
    ];
    extraModules = [
      {
        aos.filesystems.zfs = {
          enable = true;
          systemState = false;
          reservedSpace.enable = false;
        };
      }
    ];
  };
  config = evaluated.config;
  requests = config.aos.abilities.requests;
  datasetRequests = builtins.listToAttrs (
    builtins.map
    (request: lib.nameValuePair request.parameters.dataset request)
    (builtins.filter
      (request: request.parameters ? dataset)
      (builtins.attrValues requests))
  );
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
  assert !(config ? systemd);
  assert requests ? "aos-zfs-provider:pool";
  assert requests ? "aos-zfs-provider:zfs-kernel-module";
  assert requests ? "aos-zfs-provider:zfs-kernel-tunables";
  assert requests ? "aos-zfs-provider:zfs-memory-policy-lifecycle";
  assert requests ? "aos-zfs-provider:zfs-verify-parameters-lifecycle";
  assert requests ? "aos-zfs-provider:zfs-zed-lifecycle";
  assert requests ? "aos-zfs-provider:zfs-scrub-schedule";
  assert requests ? "aos-zfs-provider:zfs-scrub-activation";
  assert requests ? "aos-zfs-provider:zfs-trim-schedule";
  assert requests ? "aos-zfs-provider:zfs-health-schedule";
  assert requests ? "aos-zfs-provider:zfs-metrics-schedule";
  assert datasetRequests ? "srv/data";
  assert datasetRequests."srv/data".parameters.properties.quota == "16G";
  assert requests."aos-zfs-provider:zfs-zed-lifecycle".parameters.execution_model == "foreground";
  assert (builtins.head requests."aos-zfs-provider:zfs-zed-lifecycle".parameters.start).executable.arguments
  == ["-F" "-p" "/run/zed/zed.pid" "-s" "/var/lib/zed/zed.state"];
  assert requests."aos-zfs-provider:zfs-zed-directories".parameters.managed
  == [
    {
      path = "zed";
      purpose = "runtime";
      mode = "0755";
      retention = "service-lifetime";
    }
    {
      path = "zed";
      purpose = "state";
      mode = "0755";
      retention = "persistent";
    }
  ];
  assert config.aos.storage.managedMountPoints == ["/srv/data"];
  assert config.aos.storage.compressedSwapRecommended;
  assert config.aos.storage.hardwareMonitoringRecommended;
  assert config.aos.contributions.kernelPackages.aos-zfs-provider
  == [
    (lib.abilities.packageOutput {package = "zfs";})
  ];
  assert lib.hasInfix "/dev/disk/by-partlabel/var  /var  ext4" config.environment.etc.fstab.text;
  assert systemState.config.aos.storage.managedMountPoints
  == [
    "/var"
    "/var/lib"
    "/var/log"
  ];
  assert !(lib.hasInfix "/dev/disk/by-partlabel/var  /var  ext4" systemState.config.environment.etc.fstab.text);
  assert builtins.length kernelIntegration.config.aos.kernel.modulePackages == 1;
  assert (builtins.head kernelIntegration.config.aos.kernel.modulePackages).pname == "zfs";
  assert (builtins.head kernelIntegration.config.aos.kernel.modulePackages).kernel.version
  == kernelIntegration.config.system.build.kernel.version;
  assert builtins.elem
  (builtins.head kernelIntegration.config.aos.kernel.modulePackages)
  kernelIntegration.config.aos.boot.recovery.extraPackages;
  assert builtins.elem
  (builtins.head kernelIntegration.config.aos.kernel.modulePackages)
  kernelIntegration.config.environment.systemPackages;
  assert builtins.elem "spl.spl_kmem_cache_obj_per_slab=1" config.aos.contributions.kernelParameters.aos-zfs-provider;
  assert requests."aos-zfs-provider:zfs-kernel-tunables".parameters.values."vm.defrag_mode" == "1"; true
