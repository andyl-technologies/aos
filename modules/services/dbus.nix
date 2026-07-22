##! modules/services/dbus.nix — D-Bus system message bus
##!
##! dbus 1.14 only ships a user unit; the system dbus.service is by
##! convention distro-provided. systemd-logind, systemd-hostnamed, etc.
##! all connect to /run/dbus/system_bus_socket and refuse to start if
##! it's absent.
##!
##! Generated configuration model
##! -----------------------------
##! dbus-daemon's stock share/dbus-1/system.conf uses
##! <standard_system_servicedirs/>, which is baked at compile time to
##! ${pkgs.dbus}/share/dbus-1/{services,system-services} — both empty.
##! That means it never finds the activation entries shipped by systemd
##! at ${pkgs.systemd}/share/dbus-1/system-services, so
##! org.freedesktop.systemd1 never auto-activates on the bus and any D-Bus
##! consumer (kubelet's systemd cgroup driver, hostnamectl, timedatectl,
##! loginctl) fails.
##!
##! The fix: pkgs.dbus-conf rewrites the stock system.conf via xsltproc to
##! emit explicit <servicedir>/<includedir> lines for every package in
##! aos.services.dbus.packages. systemd is contributed automatically;
##! other modules can append (polkit, NetworkManager, etc.) by extending
##! the option.
##!
##! Operator override paths (no rebuild required)
##! ---------------------------------------------
##!   * /etc/dbus-1/system.d/*.conf  — drop-in policy files
##!   * /etc/dbus-1/system-local.conf — single-file policy override
##! After editing either, run `systemctl reload dbus.service` so dbus-daemon
##! re-reads its config without disrupting in-flight connections. Closure
##! rebuilds (a new aos.services.dbus.packages value) produce a new store
##! path for --config-file and require a `systemctl restart dbus.service`.
##!
##! suidHelper note
##! ---------------
##! AOS has no security-wrappers framework, so <servicehelper> points at
##! /bin/false. The helper is only used for non-root activation requests
##! that need privilege — a path AOS doesn't exercise today. This matches
##! NixOS's initrd codepath.
##!
##! This module contributes:
##!   * aos.users.users.messagebus + group (dbus's default runtime user)
##!   * systemd.services.dbus running dbus-daemon --system
##!   * tmpfiles entry so /run/dbus exists with the right perms
{
  config,
  pkgs,
  lib,
  ...
}: let
  cfg = config.aos.services.dbus;
  # The merged system bus config is an image-fixed artifact
  # (a function of which packages are enabled, not of host.nix). Register it as
  # a config artifact and reference the resolved value, so the on-host eval-only
  # evaluator uses the stage-1-frozen store path instead of re-building it. On a
  # normal build `frozenArtifacts` is empty, so this resolves to the same
  # `pkgs.dbus-conf {…}` derivation as before (byte-identical).
  dbusConf = config.aos.config.artifacts.dbus-system-conf;
in {
  options.aos.services.dbus.enable = lib.mkOption {
    type = lib.types.bool;
    default = true;
    description = ''
      Run the system D-Bus message bus. Needed for systemd-logind,
      hostnamed, timedated, and every other daemon that publishes or
      consumes the /run/dbus/system_bus_socket.
    '';
  };

  options.aos.services.dbus.packages = lib.mkOption {
    type = lib.types.listOf lib.types.package;
    default = [];
    example = lib.literalExpression "[ pkgs.systemd pkgs.networkmanager ]";
    description = ''
      Packages whose share/dbus-1/{system-services,system.d} contents
      should be merged into the system D-Bus configuration. systemd is
      contributed automatically when this module is enabled; other
      modules may append polkit, NetworkManager, etc. as they're added.

      Per-contributor <servicedir> entries are first-match-wins for
      activation. The operator /etc/dbus-1/system.d directory is emitted
      last, so per-contributor activation entries take precedence.
    '';
  };

  config = lib.mkIf cfg.enable {
    # Register the merged system bus config as an image-fixed config artifact
    # built during image assembly and referenced via
    # `config.aos.config.artifacts.dbus-system-conf` (see the `let` above).
    # Skip the live build entirely when the on-host evaluator injected a frozen
    # path for this artifact: `pkgs.dbus-conf` is absent from the stage-2 frozen
    # pkgs (it is a builder function, not a package), so even constructing the
    # unused thunk would error. `artifacts.dbus-system-conf` reads the frozen
    # path in that case.
    aos.config._artifactSources.dbus-system-conf =
      if config.aos.config.frozenArtifacts ? "dbus-system-conf"
      then null
      else
        pkgs.dbus-conf {
          packages = cfg.packages;
          suidHelper = "/bin/false";
          apparmor = "disabled";
        };

    # Always contribute systemd so org.freedesktop.systemd1 (plus
    # hostname1/login1/timedate1/...) is reachable on the bus. listOf
    # merges across modules, so other modules can extend this list
    # without clobbering the systemd entry.
    aos.services.dbus.packages = [pkgs.systemd];

    # Standard dbus runtime account. UID 81 matches Debian/Fedora
    # convention so hand-debugged systems look familiar.
    aos.users.users.messagebus = {
      uid = 81;
      group = "messagebus";
      home = "/var/run/dbus";
      shell = "/sbin/nologin";
      description = "D-Bus Message Bus";
      extraGroups = [];
    };
    aos.users.groups.messagebus = {
      gid = 81;
      members = [];
    };

    # System bus configuration is generated by pkgs.dbus-conf — see the
    # head comment for the operator override paths. We do NOT touch
    # /etc/dbus-1/system.conf at all; dbus-daemon reads the store path
    # passed via --config-file below.

    # /run/dbus needs to exist before dbus-daemon starts (it creates
    # the socket file there). tmpfiles runs early in stage 2.
    environment.etc."tmpfiles.d/dbus.conf".text = ''
      d /run/dbus 0755 root root -
      d /var/lib/dbus 0755 root root -
    '';

    # Socket activation. systemd creates /run/dbus/system_bus_socket
    # before dbus-daemon starts; dbus-daemon then attaches via
    # `--address=systemd:` (LISTEN_FDS handover). This is the load-
    # bearing piece for systemd-PID-1 to claim org.freedesktop.systemd1
    # on the bus: PID 1 connects to dbus through the same socket the
    # moment dbus-daemon enters the running state, and the
    # `--systemd-activation` flag on dbus.service tells dbus-daemon
    # to forward activation requests for org.freedesktop.systemd1
    # back to systemd via that connection. Without socket activation
    # systemd PID 1 never registers, kubelet's systemd cgroup driver
    # fails to create kubepods.slice, hostnamectl/timedatectl/
    # loginctl all error, etc.
    systemd.sockets."dbus" = {
      description = "D-Bus System Message Bus Socket";
      wantedBy = ["sockets.target"];
      socketConfig = {
        ListenStream = "/run/dbus/system_bus_socket";
      };
    };

    systemd.services."dbus" = {
      description = "D-Bus System Message Bus";
      wantedBy = ["multi-user.target"];
      # Reload, never restart, on a live generation switch. A `systemctl
      # restart dbus.service` tears down the system bus, which severs every
      # connected client — including the apm reconciler that is *driving the
      # switch over that very bus* (it talks to systemd via
      # /run/dbus/system_bus_socket). The reconciler then waits forever for a
      # JobRemoved it can no longer receive. dbus-daemon's ExecReload
      # (ReloadConfig, below) re-reads policy without dropping connections, so
      # the diff engine schedules a reload (X-ReloadIfChanged) instead of a
      # restart. This matches nixpkgs (services.system.dbus sets
      # reloadIfChanged = true). Tradeoff: a changed --config-file store path is
      # not picked up until the next reboot, since the running daemon keeps its
      # original argv; acceptable and identical to NixOS's behaviour. The
      # reconciler is additionally hardened against any bus-drop mid-reconcile
      # (aos-systemd drops parked waiters when the signal stream closes, and
      # connects over systemd's private socket), but not restarting the bus in
      # the first place is the primary, upstream-blessed fix.
      reloadIfChanged = true;
      requires = [
        "dbus.socket"
        "systemd-tmpfiles-setup.service"
      ];
      after = [
        "local-fs.target"
        "systemd-tmpfiles-setup.service"
        "dbus.socket"
      ];
      serviceConfig = {
        RuntimeDirectory = "dbus";
        RuntimeDirectoryMode = "0755";
        # `--address=systemd:` + `--systemd-activation` enable the
        # socket-activated handover with systemd PID 1.
        # `Type=notify` because `--systemd-activation` makes
        # dbus-daemon emit a sd_notify(READY=1) once it has accepted
        # the listen FD; without notify, systemd would mark dbus
        # `active` immediately after fork and PID 1 would race the
        # bus-name registration.
        Type = "notify";
        NotifyAccess = "main";
        ExecStart = "${pkgs.dbus}/bin/dbus-daemon --address=systemd: --nofork --nopidfile --systemd-activation --config-file=${dbusConf}/system.conf";
        ExecReload = "${pkgs.dbus}/bin/dbus-send --print-reply --system --type=method_call --dest=org.freedesktop.DBus / org.freedesktop.DBus.ReloadConfig";
        OOMScoreAdjust = "-900";
        Restart = "on-failure";
        RestartSec = "5s";
      };
      # Alias for legacy clients that look up messagebus.service.
      aliases = ["messagebus.service"];
    };
  };
}
