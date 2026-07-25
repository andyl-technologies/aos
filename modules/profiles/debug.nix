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
    }

    (lib.mkIf cfg.autologin (let
      # agetty invokes --login-program as `PROG -f USER`, matching
      # /bin/login's calling convention. Passing bash directly makes
      # bash interpret `-f` as its own flag and `USER` as a script
      # path — it exits 126. This shim drops those args and execs an
      # interactive root shell instead.
      #
      # It also seeds the session environment that /bin/login would
      # have exported from root's passwd entry. AOS ships no
      # /bin/login (util-linux is built --disable-login), and bash
      # does not synthesize HOME itself, so without this HOME/USER/
      # LOGNAME come up empty on every autologin console. (sshd
      # exports these itself, so SSH sessions are unaffected.)
      # Hardcoded to root: every agetty unit below autologins root,
      # and these values hold identically in the stage-1 initrd,
      # which has no NSS to resolve a passwd lookup through.
      #
      # This shim is an image-fixed artifact (pure function
      # of pkgs, not host.nix). Reference the resolved artifact so the on-host
      # eval-only evaluator uses the stage-1-frozen store path instead of
      # rebuilding it (`pkgs.writeShellScriptBin` is absent from the stage-2
      # frozen pkgs). On a normal build `frozenArtifacts` is empty, so this
      # resolves to the same derivation as before (byte-identical).
      autologinShell = config.aos.config.artifacts.autologin-shell;
    in {
      # Register the autologin shim as an image-fixed config artifact, guarded
      # so the stage-2 frozen pkgs never evaluates the builder.
      aos.config._artifactSources.autologin-shell =
        if config.aos.config.frozenArtifacts ? "autologin-shell"
        then null
        else
          pkgs.writeShellScriptBin "autologin-shell" ''
            export USER=root
            export LOGNAME=root
            export HOME=/root
            export SHELL=${pkgs.bash}/bin/bash
            cd "$HOME" 2>/dev/null || true
            exec ${pkgs.bash}/bin/bash -l
          '';

      # Mask the sulogin-based recovery units in the initrd. The debug
      # shells below already run an always-on autologin root shell on
      # every console (tty0/ttyS0). When a first-boot provisioning failure
      # drops stage-1 to maintenance, systemd ALSO starts
      # emergency.service — sulogin on /dev/console. With the baked-in
      # cmdline `console=ttyS0 console=tty0`, /dev/console resolves to
      # the foreground VT (tty1), which is the very screen
      # debug-shell-console is already on (it opens tty0, the
      # current-VT alias). Two processes reading one TTY split the
      # operator's keystrokes, so typed commands come back garbled
      # (e.g. `lsblk` → `bk`). The autologin shells are the recovery
      # console here, so sulogin is redundant — mask it (and rescue)
      # to leave a single reader per console.
      #
      # Gated on `autologin` (this whole block is): the debug-shell-*
      # units only exist when autologin is on, so that is exactly when
      # masking is safe. Without autologin — production, or
      # `debug.enable` alone — there are no initrd shells, and
      # emergency.service must stay unmasked as the sole recovery console.
      boot.initrd.systemd.maskedUnits = [
        "emergency.service"
        "rescue.service"
      ];

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
          SendSIGHUP = "yes";
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
          SendSIGHUP = "yes";
          TTYPath = "/dev/ttyS0";
          TTYReset = "yes";
          TTYVHangup = "yes";
        };
      };
    }))
  ]);
}
