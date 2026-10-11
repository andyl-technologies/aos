##! Focused VM checks for the chrony service.
{
  cfg,
  lib,
}: {
  description = "NTP time sync checks";
  checks =
    [
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
    ]
    ++ lib.optionals cfg.nts.enable [
      {
        name = "chrony-authentication-data";
        description = "chronyd exposes source authentication state";
        script = ''
          vm.succeed("chronyc authdata")
        '';
      }
    ];
}
