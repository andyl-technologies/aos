# tests/fleet/apm-landlock-argv.nix - Landlock wrapper argv preservation.
#
# Regression coverage for RFC-0001 P8: generated Landlock/MAC wrapper prefixes
# must not change package-authored systemd Exec* tokenization. The service
# records its argv after the wrapper chain has exec'd it.
{
  mkSystem,
  pkgs,
  ...
}: let
  system = mkSystem [
    ../../systems/server.nix
    {
      aos.packages.landlock-argv-test = {
        package = pkgs.landlock-argv-test;
        bundle = true;
        preset = false;
      };
    }
  ];
in {
  name = "apm-landlock-argv";
  timeout = 240;

  machines.vm = {
    inherit system;
    # Package activation measures PCR 15 while seeding the package profile.
    tpm = true;
    packages = ["landlock-argv-test"];
  };

  testScript = ''
    vm.wait_for_unit("aos-seed-baked-packages.service", timeout=120)
    vm.wait_until_succeeds(
        "systemctl is-active --quiet landlock-argv-test.service", timeout=120
    )
    vm.succeed("test -L /etc/systemd/system.attached/landlock-argv-test.service")

    unit = vm.succeed("cat /etc/systemd/system.attached/landlock-argv-test.service")
    assert "aos-landlock --require-abi 4" in unit, unit

    argv = vm.succeed("cat /var/lib/aos-pkg-landlock-argv-test/argv")
    expected = (
        "argc=5\n"
        "arg1=<plain>\n"
        "arg2=<two words>\n"
        "arg3=<semi;colon>\n"
        "arg4=<quote\"inner>\n"
        "arg5=<colon:value>\n"
    )
    assert argv == expected, argv
  '';
}
