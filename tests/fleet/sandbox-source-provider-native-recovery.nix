# Exercises the fixed-owner no-dispatch crash cut in an AOS QEMU guest.
# Test-only credentials and pre-cut DATA do not qualify fresh Acquire admission.
{
  lib,
  mkSystem,
  pkgs,
  ...
}: let
  fixtures = import ../vm/_sandbox-source-provider-native-recovery-fixtures.nix {inherit lib pkgs;};
  system = mkSystem [
    ../../systems/server-test.nix
    {environment.systemPackages = [fixtures];}
  ];
in {
  name = "sandbox-source-provider-native-recovery";
  timeout = 600;
  bootTimeout = 240;
  machines.vm = {inherit system;};

  testScript = ''
    vm.wait_for_unit("multi-user.target", timeout=180)
    vm.succeed("${fixtures}/bin/aos-sandbox-source-provider-credentials-vm-probe install")
    output = vm.succeed(
        "RUST_MIN_STACK=33554432 "
        "AOS_NATIVE_VM_CREDENTIAL_PROBE=${fixtures}/bin/aos-sandbox-source-provider-credentials-vm-probe "
        "AOS_NATIVE_VM_PRECUT_SEEDER=${fixtures}/bin/aos-sandbox-source-provider-precut-vm-seed "
        "AOS_NATIVE_VM_PROVIDER_CHILD=${fixtures}/bin/aos-sandbox-source-provider-owner-vm-server "
        "${fixtures}/bin/aos-sandbox-mount-native-recovery-vm-tests "
        "--ignored --exact "
        "source_acquisition::reservation::native_recovery_fixture::installed_vm::fixed_owner_native_recovery_vm_cut "
        "--nocapture",
        timeout=180,
    )
    assert "test result: ok. 1 passed" in output, output
    assert "fixed_owner_native_recovery_vm_cut ... ok" in output, output
  '';
}
