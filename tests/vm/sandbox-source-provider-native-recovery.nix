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
  fixtures = pkgs.mkCargoPackage {
    pname = "aos-sandbox-source-provider-native-recovery-vm-fixtures";
    version = "0.0.0";
    src = import ../../pkgs/tools/aos/_workspace-source.nix {inherit lib;};
    cargoDeps = pkgs.aos.passthru.cargoDeps;
    cargoRoot = "crates";
    buildType = "debug";
    cargoBuildCommands = [
      "build --frozen --offline -j$NIX_BUILD_CORES -p aos-sandbox-service-journal-probe --bin aos-sandbox-source-provider-credentials-vm-probe --bin aos-sandbox-source-provider-precut-vm-seed --bin aos-sandbox-source-provider-owner-vm-server"
      "test --no-run --lib --frozen --offline -j$NIX_BUILD_CORES -p aos-sandbox-mount"
    ];
    doCheck = false;
    buildDeps = [pkgs.protobuf];
    cargoEnv.PROTOC = "${pkgs.protobuf}/bin/protoc";
    runtimeDeps = [];
    postInstall = ''
      count=0
      for candidate in target/debug/deps/aos_sandbox_mount-*; do
        if [ -f "$candidate" ] && [ -x "$candidate" ]; then
          install -m 0755 "$candidate" "$out/bin/aos-sandbox-mount-native-recovery-vm-tests"
          count=$((count + 1))
        fi
      done
      if [ "$count" -ne 1 ]; then
        echo "expected one Mount unit-test executable, found $count" >&2
        exit 1
      fi
    '';
  };
in
  testing.mkVMTest {
    name = "sandbox-source-provider-native-recovery";
    rootfsDeps = [fixtures pkgs.coreutils];
    memory = 768;
    testScript = ''
      set -eu
      exec > /dev/ttyS0 2>&1
      set -x
      unset LD_LIBRARY_PATH

      test "$(id -u)" = 0
      ${fixtures}/bin/aos-sandbox-source-provider-credentials-vm-probe install

      export AOS_NATIVE_VM_CREDENTIAL_PROBE=${fixtures}/bin/aos-sandbox-source-provider-credentials-vm-probe
      export AOS_NATIVE_VM_PRECUT_SEEDER=${fixtures}/bin/aos-sandbox-source-provider-precut-vm-seed
      export AOS_NATIVE_VM_PROVIDER_CHILD=${fixtures}/bin/aos-sandbox-source-provider-owner-vm-server
      ${fixtures}/bin/aos-sandbox-mount-native-recovery-vm-tests \
        --ignored --exact \
        source_acquisition::reservation::native_recovery_fixture::installed_vm::fixed_owner_native_recovery_vm_cut \
        --nocapture
    '';
  }
