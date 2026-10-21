# Installed fixed-owner qualification of native no-dispatch recovery only.
#
# The deterministic authority material and pre-cut writer live exclusively in
# VM fixture executables. Neither is compiled into a production service. This
# check does not qualify fresh Acquire admission or a SourceRoot descriptor.
{
  lib,
  testing,
  pkgs,
}: let
  fixtures = import ./_sandbox-source-provider-native-recovery-fixtures.nix {inherit lib pkgs;};
in
  testing.mkVMTest {
    name = "sandbox-source-provider-native-recovery";
    rootfsDeps = [fixtures pkgs.coreutils pkgs.util-linux];
    memory = 768;
    testScript = ''
      set -eu
      exec > /dev/ttyS0 2>&1
      set -x
      unset LD_LIBRARY_PATH

      test "$(id -u)" = 0
      # This headless guest has no manager to mount the unified hierarchy.
      # Credentials bind the actual kernel cgroup path observed below.
      mkdir -p /sys/fs/cgroup
      ${pkgs.util-linux}/bin/mount -t cgroup2 none /sys/fs/cgroup
      ${fixtures}/bin/aos-sandbox-source-provider-credentials-vm-probe install

      export AOS_NATIVE_VM_CREDENTIAL_PROBE=${fixtures}/bin/aos-sandbox-source-provider-credentials-vm-probe
      export AOS_NATIVE_VM_PRECUT_SEEDER=${fixtures}/bin/aos-sandbox-source-provider-precut-vm-seed
      export AOS_NATIVE_VM_PROVIDER_CHILD=${fixtures}/bin/aos-sandbox-source-provider-owner-vm-server
      RUST_MIN_STACK=33554432 \
      ${fixtures}/bin/aos-sandbox-mount-native-recovery-vm-tests \
        --ignored --exact \
        source_acquisition::reservation::native_recovery_fixture::installed_vm::fixed_owner_native_recovery_vm_cut \
        --nocapture
    '';
  }
