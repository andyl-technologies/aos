# tests/fleet/apm-landlock-argv.nix - Native service argv preservation.
#
# The service-management handler renders package-authored Exec* arguments into
# the native systemd unit. Each argument must reach the process unchanged,
# including whitespace, shell metacharacters, quotes, and colons. Package
# service units run the declared executable directly; no Landlock wrapper is
# inserted in front of it. The recorder writes the argv it received into its
# persistent state directory.
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
      };
    }
  ];
in {
  name = "apm-landlock-argv";
  timeout = 600;

  machines.vm = {
    inherit system;
    # Package activation measures PCR 15 while seeding the package profile.
    tpm = true;
    packages = ["landlock-argv-test"];
  };

  testScript = ''
    unit_name = "landlock-argv-test.main.service"

    vm.wait_for_unit("aos-activate.service", timeout=300)
    vm.wait_until_succeeds(
        f"systemctl is-active --quiet {unit_name}", timeout=120
    )

    fragment = vm.succeed(
        f"systemctl show -p FragmentPath --value {unit_name}"
    ).strip()
    assert fragment == f"/etc/systemd/system/{unit_name}", fragment
    unit = vm.succeed(f"cat {fragment}")
    assert "aos-landlock" not in unit, unit

    # The executable is the first ExecStart token, followed by each declared
    # argument as one systemd-quoted word.
    exec_start = [
        line for line in unit.splitlines() if line.startswith("ExecStart=")
    ]
    assert len(exec_start) == 1, exec_start
    executable, _, arguments = exec_start[0].removeprefix("ExecStart=").partition(" ")
    assert executable.endswith('/bin/landlock-argv-test-recorder"'), exec_start
    expected_arguments = (
        '"/var/lib/landlock-argv-test" "plain" "two words" "semi;colon" '
        '"quote\\"inner" "colon:value"'
    )
    assert arguments == expected_arguments, arguments

    argv = vm.succeed("cat /var/lib/landlock-argv-test/argv")
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
