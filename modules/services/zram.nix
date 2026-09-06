##! modules/system/zram.nix — Compressed swap backed by zram
{
  config,
  lib,
  pkgs,
  ...
}: let
  cfg = config.aos.zram;
in {
  options.aos.zram = {
    enable = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = "Create a compressed in-memory swap device.";
    };

    size = lib.mkOption {
      type = lib.types.strMatching "[A-Za-z0-9 ()*/+.,_-]+";
      default = "min(ram / 2, 4096)";
      description = "Arithmetic expression that sets the zram device size in MiB.";
    };

    compressionAlgorithms = lib.mkOption {
      type = lib.types.listOf (lib.types.strMatching "[A-Za-z0-9_+().,=-]+");
      default = ["zstd"];
      description = "Compression algorithms tried in priority order.";
    };

    priority = lib.mkOption {
      type = lib.types.int;
      default = 100;
      description = "Swap priority assigned to the zram device.";
    };
  };

  config = lib.mkIf cfg.enable {
    assertions = [
      {
        assertion = cfg.priority >= -1 && cfg.priority <= 32767;
        message = "aos.zram.priority must be between -1 and 32767";
      }
      {
        assertion = cfg.compressionAlgorithms != [];
        message = "aos.zram.compressionAlgorithms must contain at least one algorithm";
      }
    ];

    aos.kernel.modules = ["zram"];
    environment.systemPackages = [pkgs.zram-generator];
    systemd.packages = [pkgs.zram-generator];

    environment.etc = {
      "systemd/system-generators/zram-generator".source = "${pkgs.zram-generator}/lib/systemd/system-generators/zram-generator";
      "systemd/zram-generator.conf".text = ''
        [zram0]
        zram-size = ${cfg.size}
        compression-algorithm = ${lib.concatStringsSep " " cfg.compressionAlgorithms}
        swap-priority = ${toString cfg.priority}
      '';
    };

    # zram-generator delegates swap formatting to systemd-makefs, which finds
    # mkswap through PATH. If formatting cannot start, the first attempt has
    # already initialized the device and later retries fail with EBUSY while
    # changing its compression algorithm.
    systemd.services."systemd-zram-setup@" = {
      overrideStrategy = "asDropin";
      path = [pkgs.util-linux];
    };

    system.checks.zram = {
      description = "Compressed swap checks";
      checks = [
        {
          name = "zram-swap-active";
          description = "The generated zram swap unit activates";
          script = ''
            vm.wait_until_succeeds(
                "systemctl is-active --quiet dev-zram0.swap", timeout=30
            )
            vm.succeed("test -b /dev/zram0")
            vm.succeed("test $(cat /sys/block/zram0/disksize) -gt 0")
          '';
        }
      ];
    };
  };
}
