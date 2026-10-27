# Effective system-bus policy for exact unit lifetime ownership.
{
  mkSystem,
  pkgs,
  ...
}: let
  unit = "aos-reference-policy-probe.service";
  probe = pkgs.mkDerivation {
    pname = "aos-systemd-unit-reference-policy-probe";
    version = "1";
    src = ../sandbox/systemd-unit-reference-policy.c;
    runtimeDeps = [pkgs.systemd];
    phases = [
      {
        name = "build";
        script = ''
          $CC -std=c17 -Wall -Wextra -Werror "$src" -lsystemd -o policy-probe
        '';
      }
      {
        name = "install";
        script = ''
          mkdir -p "$out/bin"
          install -m 0755 policy-probe "$out/bin/"
        '';
      }
    ];
    meta.license = "Apache-2.0";
  };
  system = mkSystem [
    ../../systems/server-test.nix
    {
      environment.systemPackages = [pkgs.systemd pkgs.util-linux];

      aos.users.groups.reference-policy-controller = {
        gid = 811;
        members = [];
      };
      aos.users.users.reference-policy-controller = {
        uid = 811;
        group = "reference-policy-controller";
        home = "/";
        shell = "/sbin/nologin";
        description = "Systemd reference-policy controller probe";
        extraGroups = [];
      };
      aos.users.groups.reference-policy-peer = {
        gid = 812;
        members = [];
      };
      aos.users.users.reference-policy-peer = {
        uid = 812;
        group = "reference-policy-peer";
        home = "/";
        shell = "/sbin/nologin";
        description = "Systemd reference-policy second peer";
        extraGroups = [];
      };
    }
  ];
in {
  name = "systemd-unit-reference-policy";
  timeout = 120;
  machines.vm = {
    inherit system;
    extraClosures = [probe];
  };
  testScript = ''
    vm.wait_for_unit("multi-user.target", timeout=60)
    vm.succeed("test -f ${pkgs.systemd}/share/aos/unit-reference-policy-v1")
    vm.succeed("test -x ${probe}/bin/policy-probe")
    vm.succeed(
        "${pkgs.systemd}/bin/systemd-run "
        "--unit=${unit} --collect --remain-after-exit "
        "${pkgs.coreutils}/bin/true"
    )
    vm.wait_for_unit("${unit}", timeout=30)

    operations = [
        "manager-ref",
        "manager-unref",
        "unit-ref",
        "unit-unref",
        "start",
        "restart",
        "stop",
        "start-transient",
    ]
    for uid in (811, 812):
        for operation in operations:
            output = vm.succeed(
                "${pkgs.util-linux}/bin/setpriv "
                f"--reuid={uid} --regid={uid} --clear-groups "
                "${probe}/bin/policy-probe "
                f"{operation} ${unit}"
            )
            assert (
                f"ACCESS_DENIED {operation} org.freedesktop.DBus.Error.AccessDenied"
                in output
            ), output

    collection = vm.succeed(
        "${probe}/bin/policy-probe root-collection ${unit}",
        timeout=30,
    )
    assert "ROOT_REFERENCE_COLLECTION_OK" in collection, collection
    vm.fail("systemctl status ${unit}")
  '';
}
