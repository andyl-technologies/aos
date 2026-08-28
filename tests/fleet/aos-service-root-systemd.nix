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
    vm.succeed("systemctl stop aos-service-root-systemd-test.service")
    vm.succeed("test ! -e /run/aos/service-roots/systemd-test")
    vm.succeed("grep -qx immutable ${payload}/share/payload")
  '';
}
