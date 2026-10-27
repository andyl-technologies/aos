# Runs the complete ordinary Domain unit suite with real protected ancestry.
# This component check supplies no production Controller admission or role.
{
  lib,
  mkSystem,
  pkgs,
  ...
}: let
  tests = import ./_sandbox-native-unit-tests.nix {inherit lib pkgs;};
  system = mkSystem [
    ../../systems/server-test.nix
    {environment.systemPackages = [tests pkgs.util-linux];}
  ];
in {
  name = "sandbox-domain-native-journal";
  timeout = 900;
  bootTimeout = 240;
  machines.vm = {inherit system;};

  testScript = ''
    import re
    import tomllib

    # Every Domain case excluded from the build sandbox must execute here.
    # Exact names make missing or conditionally compiled cases fail closed.
    with open("${../../crates/.config/nextest.toml}", "rb") as stream:
        expression = tomllib.load(stream)["profile"]["nix-sandbox"]["default-filter"]
    native_groups = dict(re.findall(
        r"\(package\(=([^)]+)\) & \((.*?)\)\)", expression, re.S,
    ))
    native_cases = re.findall(
        r"test\(=([^)]+)\)", native_groups["aos-sandbox-controller-domain"],
    )
    assert native_cases, "missing required Domain native cases"

    vm.wait_for_unit("multi-user.target", timeout=180)

    # Fixtures create their journals beside current_exe(). Keep the store
    # immutable and run under an unprivileged UID in its private directory,
    # reached through actual root-owned guest ancestry.
    vm.succeed("install -d -m 0700 -o 1000 -g 1000 /var/lib/aos-sandbox-domain-tests")
    vm.succeed("install -m 0755 ${tests}/bin/sandbox-unit-tests /var/lib/aos-sandbox-domain-tests/suite")
    output = vm.succeed(
        "cd /var/lib/aos-sandbox-domain-tests && "
        "RUST_MIN_STACK=33554432 ${pkgs.util-linux}/bin/setpriv "
        "--reuid=1000 --regid=1000 --clear-groups "
        "/var/lib/aos-sandbox-domain-tests/suite "
        "--test-threads=1",
        timeout=600,
    )
    assert "test result: ok." in output, output
    assert "0 filtered out" in output, output
    for name in native_cases:
        assert f"test {name} ... ok" in output, output
  '';
}
