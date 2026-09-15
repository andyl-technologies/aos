##! Selects the package-owned chrony service module for static systems.
{config, lib, pkgs, ...}: {
  environment.systemPackages = [pkgs.chrony];

  system.checks.chrony = lib.mkIf config.aos.services.chrony.enable {
    description = "NTP time sync checks";
    checks = [
      {
        name = "chronyd-responsive";
        description = "chronyd accepts control queries";
        script = ''
          vm.wait_until_succeeds("chronyc tracking", timeout=30)
        '';
      }
      {
        name = "chrony-sources";
        description = "chronyd exposes its configured time sources";
        script = ''
          vm.succeed("chronyc sources")
        '';
      }
    ] ++ lib.optionals config.aos.services.chrony.nts.enable [
      {
        name = "chrony-authentication-data";
        description = "chronyd exposes source authentication state";
        script = ''
          vm.succeed("chronyc authdata")
        '';
      }
    ];
  };
}
