##! modules/services/zram.nix — Selects zram-generator for host integration
{
  config,
  lib,
  pkgs,
  ...
}: {
  # Selecting the package admits its authenticated module into the final
  # fixed point. The package module owns zram configuration and requirements.
  environment.systemPackages = [pkgs.zram-generator];

  system.checks.zram = lib.mkIf (config.aos.zram.enable or false) {
    description = "Compressed swap checks";
    checks = [
      {
        name = "zram-swap-device";
        description = "The configured zram swap device is initialized";
        script = ''
          vm.wait_until_succeeds("test -b /dev/zram0", timeout=30)
          vm.succeed("test $(cat /sys/block/zram0/disksize) -gt 0")
        '';
      }
    ];
  };
}
