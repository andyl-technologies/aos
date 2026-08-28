# tests/fleet/aos-service-root-systemd.nix — Trusted overlay helper unit context.
{
  mkSystem,
  pkgs,
  ...
}: let
  payload = pkgs.runCommand "aos-service-root-systemd-payload" {} ''
    mkdir -p $out/share
    printf immutable > $out/share/payload
  '';
  system = mkSystem [
    ../../systems/server-test.nix
    {
      environment.systemPackages = [
        pkgs.aos-service-root
        pkgs.util-linux
        payload
      ];

      # This is the exact privilege and sandbox contract emitted for every
      # confined, non-verity package service root preparation unit.
      systemd.services.aos-service-root-systemd-test = {
        serviceConfig = {
          Type = "oneshot";
          RemainAfterExit = true;
          ExecStart = "${pkgs.aos-service-root}/bin/aos-service-root prepare systemd-test ${payload} workload.service";
          ExecStop = "${pkgs.aos-service-root}/bin/aos-service-root cleanup systemd-test ${payload} workload.service";
          ExecStopPost = "${pkgs.aos-service-root}/bin/aos-service-root cleanup systemd-test ${payload} workload.service";
          CapabilityBoundingSet = "CAP_DAC_OVERRIDE CAP_MKNOD CAP_SYS_ADMIN";
          AmbientCapabilities = "CAP_DAC_OVERRIDE CAP_MKNOD CAP_SYS_ADMIN";
          PrivateMounts = false;
          NoNewPrivileges = false;
          RestrictAddressFamilies = "AF_UNIX";
          UMask = "0077";
        };
      };

      # Exercise the consumer side of the contract as an unprivileged dynamic
      # identity. This catches traversal failures in the host-side root path
      # as well as missing systemd directory and store bind mountpoints.
      systemd.services.workload = {
        after = ["aos-service-root-systemd-test.service"];
        requires = ["aos-service-root-systemd-test.service"];
        serviceConfig = {
          Type = "oneshot";
          RemainAfterExit = true;
          DynamicUser = true;
          RootDirectory = "/run/aos/service-roots/systemd-test/workload.service/merged";
          BindReadOnlyPaths = "/nix/store";
          StateDirectory = "aos-service-root-workload";
          RuntimeDirectory = "aos-service-root-workload";
          LogsDirectory = "aos-service-root-workload";
          ProtectSystem = "strict";
          ExecStart = "${pkgs.bash}/bin/bash -c 'grep -qx immutable /share/payload && printf state > /var/lib/aos-service-root-workload/state && printf runtime > /run/aos-service-root-workload/runtime && printf log > /var/log/aos-service-root-workload/log'";
        };
      };
    }
  ];
in {
  name = "aos-service-root-systemd";
  timeout = 240;

  machines.vm = {inherit system;};

  testScript = ''
    vm.wait_for_unit("multi-user.target", timeout=120)
    vm.succeed("systemctl start aos-service-root-systemd-test.service")
    vm.succeed(
        "test \"$(findmnt -n -o FSTYPE "
        "/run/aos/service-roots/systemd-test/workload.service/merged)\" = overlay"
    )
    vm.succeed(
        "grep -qx immutable "
        "/run/aos/service-roots/systemd-test/workload.service/merged/share/payload"
    )
    vm.succeed("test \"$(stat -c %a /run/aos/service-roots/systemd-test)\" = 711")
    vm.succeed("test \"$(stat -c %a /run/aos/service-roots/systemd-test/workload.service)\" = 711")
    vm.succeed("test \"$(stat -c %a /run/aos/service-roots/systemd-test/workload.service/merged)\" = 711")
    vm.succeed("test \"$(stat -c %a /run/aos/service-roots/systemd-test/workload.service/upper)\" = 700")
    vm.succeed("test \"$(stat -c %a /run/aos/service-roots/systemd-test/workload.service/work)\" = 700")
    try:
        vm.succeed("systemctl start workload.service")
    except Exception:
        print(vm.succeed(
            "systemctl status --no-pager --full workload.service || true; "
            "journalctl --no-pager -u workload.service -n 100 || true; "
            "namei -l /run/aos/service-roots/systemd-test/workload.service/merged || true; "
            "findmnt /run/aos/service-roots/systemd-test/workload.service/merged || true"
        ))
        raise
    vm.succeed("systemctl is-active --quiet workload.service")
    vm.succeed("grep -qx state /var/lib/private/aos-service-root-workload/state")
    vm.succeed("grep -qx runtime /run/aos-service-root-workload/runtime")
    vm.succeed("grep -qx log /var/log/private/aos-service-root-workload/log")
    vm.succeed("grep -qx immutable ${payload}/share/payload")
    vm.succeed("systemctl stop workload.service")
    vm.succeed("systemctl stop aos-service-root-systemd-test.service")
    vm.succeed("test ! -e /run/aos/service-roots/systemd-test")
    vm.succeed("grep -qx immutable ${payload}/share/payload")
  '';
}
