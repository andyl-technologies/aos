# Exercise systemd's task guard and kernel set-ID denials, including borrowed SQPOLL.
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

  sqpollProbe = pkgs.mkDerivation {
    pname = "aos-systemd-no-setid-sqpoll-probe";
    version = "1";
    src = ../sandbox/systemd-no-setid-sqpoll.c;
    buildDeps = [pkgs.linux-headers pkgs.liburing];
    runtimeDeps = [pkgs.liburing];
    phases = [
      {
        name = "build";
        script = ''
          $CC -std=c17 -Wall -Wextra -Werror "$src" -luring -o no-setid-sqpoll-probe
        '';
      }
      {
        name = "install";
        script = ''
          mkdir -p "$out/bin"
          install -m 0755 no-setid-sqpoll-probe "$out/bin/"
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
    extraClosures = [probe sqpollProbe];
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
    assert "AOS_NO_SETID_INHERITED_OK" in output, output

    direct_output = vm.succeed(
        "${pkgs.systemd}/bin/systemd-run --pipe --wait --collect "
        "--unit=aos-no-setid-direct-probe "
        "--property=RestrictSUIDSGID=no "
        "${probe}/bin/no-setid-guard-probe --direct",
        timeout=30,
    )
    assert "AOS_NO_SETID_DIRECT_OK" in direct_output, direct_output

    sqpoll_output = vm.succeed(
        "${pkgs.systemd}/bin/systemd-run --pipe --wait --collect "
        "--unit=aos-no-setid-sqpoll-probe "
        "--property=RestrictSUIDSGID=no "
        "--property=SystemCallFilter=~io_uring_enter "
        "--property=SystemCallErrorNumber=EPERM "
        "${sqpollProbe}/bin/no-setid-sqpoll-probe",
        timeout=30,
    )
    assert "AOS_NO_SETID_SQPOLL_OK" in sqpoll_output, sqpoll_output
  '';
}
