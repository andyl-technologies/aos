# Runs the complete ordinary Domain unit suite with real protected ancestry.
# This component check supplies no production Controller admission or role.
{
  lib,
  mkSystem,
  pkgs,
  ...
}: let
  tests = import ./_sandbox-domain-unit-tests.nix {inherit lib pkgs;};
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
    vm.wait_for_unit("multi-user.target", timeout=180)

    # Fixtures create their journals beside current_exe(). Keep the store
    # immutable and run under an unprivileged UID in its private directory,
    # reached through actual root-owned guest ancestry.
    vm.succeed("install -d -m 0700 -o 1000 -g 1000 /var/lib/aos-sandbox-domain-tests")
    vm.succeed("install -m 0755 ${tests}/bin/sandbox-domain-unit-tests /var/lib/aos-sandbox-domain-tests/suite")
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
    for name in (
        "journal::protected_storage::currentness::tests::one_native_ancestry_binds_actual_writers_and_rejects_different_directory_uid_or_path",
        "journal::root_readonly_model::tests::saved_challenge_refusal_preserves_acquisition_and_owed_names_after_mount_failure",
    ):
        assert f"test {name} ... ok" in output, output
  '';
}
