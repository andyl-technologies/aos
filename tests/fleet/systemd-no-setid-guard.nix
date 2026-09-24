# The kernel task guard must allow openat2 without allowing set-ID creation.
{
  mkSystem,
  pkgs,
  ...
}: let
  probe = pkgs.mkDerivation {
    pname = "aos-systemd-no-setid-guard-probe";
    version = "1";
    src = ../sandbox/systemd-no-setid-guard.c;
    buildDeps = [pkgs.linux-headers];
    runtimeDeps = [];
    phases = [
      {
        name = "build";
        script = ''
          $CC -std=c17 -Wall -Wextra -Werror "$src" -o no-setid-guard-probe
        '';
      }
      {
        name = "install";
        script = ''
          mkdir -p "$out/bin"
          install -m 0755 no-setid-guard-probe "$out/bin/"
        '';
      }
    ];
    meta.license = "Apache-2.0";
  };

  system = mkSystem [../../systems/server-test.nix];
in {
  name = "systemd-no-setid-guard";
  timeout = 120;
  machines.vm = {
    inherit system;
    extraClosures = [probe];
  };
  testScript = ''
    vm.wait_for_unit("multi-user.target", timeout=60)

    output = vm.succeed(
        "${pkgs.systemd}/bin/systemd-run --pipe --wait --collect "
        "--unit=aos-no-setid-guard-probe "
        "--property=DynamicUser=yes "
        "--property=NoNewPrivileges=yes "
        "--property=RestrictSUIDSGID=yes "
        "${probe}/bin/no-setid-guard-probe",
        timeout=30,
    )
    assert "AOS_NO_SETID_GUARD_OK" in output, output
  '';
}
