# Executes every native Policy unit test with real protected guest ancestry.
{
  lib,
  mkSystem,
  pkgs,
  ...
}: let
  tests = import ./_sandbox-native-unit-tests.nix {
    inherit lib pkgs;
    crate = "aos-sandbox-policy";
    features = ["aos-sandbox-policy/native-journal"];
  };
  system = mkSystem [
    ../../systems/server-test.nix
    {environment.systemPackages = [tests pkgs.util-linux];}
  ];
in {
  name = "sandbox-policy-native-journal";
  timeout = 900;
  bootTimeout = 240;
  machines.vm = {inherit system;};

  testScript = ''
    vm.wait_for_unit("multi-user.target", timeout=180)
    vm.succeed("install -d -m 0700 -o 1000 -g 1000 /var/lib/aos-sandbox-policy-tests")
    vm.succeed("install -m 0755 ${tests}/bin/sandbox-unit-tests /var/lib/aos-sandbox-policy-tests/suite")
    output = vm.succeed(
        "cd /var/lib/aos-sandbox-policy-tests && "
        "RUST_MIN_STACK=33554432 ${pkgs.util-linux}/bin/setpriv "
        "--reuid=1000 --regid=1000 --clear-groups "
        "/var/lib/aos-sandbox-policy-tests/suite --test-threads=1",
        timeout=600,
    )
    assert "test result: ok." in output, output
    assert "0 filtered out" in output, output
    for name in (
        "native::readonly::completed::tests::incomplete_native_handoff_returns_the_same_live_file_owner",
        "native::readonly::completed::tests::an_already_transferred_model_cannot_also_retire_as_complete_data",
    ):
        assert f"test {name} ... ok" in output, output
  '';
}
