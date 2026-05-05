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
}: let
  cfg = config.aos.profiles.debug;
in {
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

      # Activate the test-http-server role's runtime side effects
      # (systemPackages, system.checks). The role's ignition config is
      # computed regardless; this flip adds the integration test to the
      # system's checks set.
      aos.roles.test-http-server.enable = true;
    }

    (lib.mkIf cfg.autologin (let
      # agetty invokes --login-program as `PROG -f USER`, matching
      # /bin/login's calling convention. Passing bash directly makes
      # bash interpret `-f` as its own flag and `USER` as a script
      # path — it exits 126. Tiny shim drops the args and execs an
      # interactive root shell instead.
      autologinShell = pkgs.writeShellScriptBin "autologin-shell" ''
        exec ${pkgs.bash}/bin/bash -l
      '';
    in {
      # Initrd debug shells — start early so you can inspect systemd
      # state before switch-root. One on the serial console (ttyS0)
      # and one on the VGA console (tty0 / GTK window).
      boot.initrd.systemd.services."debug-shell-serial" = {
        description = "Initrd Debug Shell on ttyS0";
        wantedBy = ["sysinit.target"];
        unitConfig.DefaultDependencies = false;
        serviceConfig = {
          ExecStart = "${pkgs.util-linux}/sbin/agetty --autologin root --login-program=${autologinShell}/bin/autologin-shell -s ttyS0 115200 vt100";
          Restart = "always";
          RestartSec = "0";
          TTYPath = "/dev/ttyS0";
          TTYReset = "yes";
          TTYVHangup = "yes";
        };
      };
      boot.initrd.systemd.services."debug-shell-console" = {
        description = "Initrd Debug Shell on tty0";
        wantedBy = ["sysinit.target"];
        unitConfig.DefaultDependencies = false;
        serviceConfig = {
          ExecStart = "${pkgs.util-linux}/sbin/agetty --autologin root --login-program=${autologinShell}/bin/autologin-shell --noclear tty0 linux";
          Restart = "always";
          RestartSec = "0";
          TTYPath = "/dev/tty0";
          TTYReset = "yes";
          TTYVHangup = "yes";
        };
      };
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
      # serial-getty@.service template units. `--autologin root`
      # would have agetty exec /bin/login, which AOS doesn't ship
      # (util-linux is built with --disable-login), so we use
      # `--login-program=${bash}` to exec bash directly as root —
      # agetty already sets up the controlling TTY with euid 0.
      systemd.services."getty@tty1" = {
        description = "Autologin Getty on tty1";
        wantedBy = ["getty.target"];
        after = ["systemd-user-sessions.service"];
        serviceConfig = {
          Type = "idle";
          ExecStart = [
            ""
            "${pkgs.util-linux}/sbin/agetty --autologin root --login-program=${autologinShell}/bin/autologin-shell --noclear tty1 linux"
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
        wantedBy = ["getty.target"];
        after = ["systemd-user-sessions.service"];
        serviceConfig = {
          Type = "idle";
          ExecStart = [
            ""
            "${pkgs.util-linux}/sbin/agetty --autologin root --login-program=${autologinShell}/bin/autologin-shell -s ttyS0 115200 vt100"
          ];
          Restart = "always";
          RestartSec = "0";
          TTYPath = "/dev/ttyS0";
          TTYReset = "yes";
          TTYVHangup = "yes";
        };
      };
    }))
  ]);
}
