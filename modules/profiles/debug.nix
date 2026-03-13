##! modules/profiles/debug.nix — Debug tools profile
##!
##! Adds diagnostic and debugging tools to the system. Sets the security
##! level to "debug" (permissive SELinux, core dumps enabled, no lockdown).
{
  config,
  pkgs,
  lib,
  ...
}:
let
  cfg = config.aos.profiles.debug;
in
{
  options.aos.profiles.debug = {
    enable = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = ''
        Enable the debug profile. Adds diagnostic tools (strace, tcpdump,
        hdparm, smartmontools, etc.) and sets security to debug level.
      '';
    };
  };

  config = lib.mkIf cfg.enable {
    # Security: debug level (permissive SELinux, core dumps, no lockdown)
    aos.security.level = lib.mkDefault "debug";

    # Debug and diagnostic tools
    environment.systemPackages = [
      pkgs.strace
      pkgs.tcpdump
      pkgs.lsof
      pkgs.hdparm
      pkgs.smartmontools
      pkgs.procps-ng
      pkgs.conntrack-tools
      pkgs.iproute2
      pkgs.ethtool
      pkgs.curl
      pkgs.jq
    ];
  };
}
