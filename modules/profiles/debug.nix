##! modules/profiles/debug.nix — Debug tools profile
##!
##! Adds diagnostic and debugging tools to the system. Sets the security
##! level to "debug" (permissive SELinux, core dumps enabled, no lockdown).
##! Optionally enables passwordless root login on tty1 + ttyS0 for local
##! VM testing when `aos.profiles.debug.autologin` is true.
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

    autologin = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = ''
        Unlock root's password and auto-login as root on tty1 and the
        primary serial console (ttyS0). For local VM testing only —
        NEVER enable this on a system exposed to an untrusted network.
      '';
    };
  };

  config = lib.mkIf cfg.enable (lib.mkMerge [
    {
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
    }

    (lib.mkIf cfg.autologin {
      # Unlock root. The empty second field in shadow(5) means "no
      # password required" — login accepts a bare username.
      environment.etc."shadow" = lib.mkForce {
        text = ''
          root:::0:99999:7:::
          nobody:!*::0:99999:7:::
        '';
        mode = "0000";
      };

      # Instance overrides for the upstream getty@.service and
      # serial-getty@.service template units — tell agetty to skip
      # the login prompt and start root's session immediately.
      systemd.services."getty@tty1" = {
        description = "Autologin Getty on tty1";
        wantedBy = [ "getty.target" ];
        after = [ "systemd-user-sessions.service" ];
        serviceConfig = {
          Type = "idle";
          ExecStart = [
            ""
            "${pkgs.util-linux}/sbin/agetty --autologin root --noclear tty1 linux"
          ];
          Restart = "always";
          RestartSec = "0";
          TTYPath = "/dev/tty1";
          TTYReset = "yes";
          TTYVHangup = "yes";
          TTYVTDisallocate = "yes";
          UtmpIdentifier = "tty1";
        };
      };

      systemd.services."serial-getty@ttyS0" = {
        description = "Autologin Serial Getty on ttyS0";
        wantedBy = [ "getty.target" ];
        after = [ "systemd-user-sessions.service" ];
        serviceConfig = {
          Type = "idle";
          ExecStart = [
            ""
            "${pkgs.util-linux}/sbin/agetty --autologin root -s ttyS0 115200 vt100"
          ];
          Restart = "always";
          RestartSec = "0";
          TTYPath = "/dev/ttyS0";
          TTYReset = "yes";
          TTYVHangup = "yes";
        };
      };
    })
  ]);
}
