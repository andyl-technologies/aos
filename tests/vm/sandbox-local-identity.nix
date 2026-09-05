# Real cgroup-v2 qualification kept outside the hermetic package test sandbox.
{
  lib,
  testing,
  pkgs,
}: let
  packages = [
    "aos-sandbox"
    "aos-sandbox-linux"
    "aos-sandbox-host"
    "aos-sandbox-mount"
  ];
  packageFlags = builtins.concatStringsSep " " (map (name: "-p ${name}") packages);
  features = builtins.concatStringsSep "," (map (name: "${name}/kernel-tests") packages);

  fixtures = pkgs.mkCargoPackage {
    pname = "aos-sandbox-local-identity-tests";
    version = "0.1.0";
    src = import ../../pkgs/tools/aos/_workspace-source.nix {inherit lib;};
    cargoDeps = pkgs.aos.passthru.cargoDeps;
    cargoRoot = "crates";
    buildType = "debug";
    cargoBuildCommands = [
      "test --no-run --lib --frozen --offline -j$NIX_BUILD_CORES ${packageFlags} --features ${features}"
    ];
    # Normal tests run in the build sandbox without the feature. The explicitly
    # enabled kernel fixtures run only in the guest, never against host cgroups.
    doCheck = true;
    cargoTestFlags = "${packageFlags} --lib";
    installBins = false;
    buildDeps = [pkgs.protobuf];
    runtimeDeps = [];
    cargoEnv.PROTOC = "${pkgs.protobuf}/bin/protoc";
    # Preserve the feature-enabled executables before the check phase compiles
    # distinct default-feature test binaries into the same Cargo target tree.
    postBuild = ''
      mkdir kernel-fixtures
      for crate in aos_sandbox aos_sandbox_linux aos_sandbox_host aos_sandbox_mount; do
        count=0
        for candidate in target/debug/deps/"$crate"-*; do
          if [ -f "$candidate" ] && [ -x "$candidate" ]; then
            install -m 0755 "$candidate" "kernel-fixtures/$crate"
            count=$((count + 1))
          fi
        done
        if [ "$count" -ne 1 ]; then
          echo "expected exactly one $crate unit-test executable, found $count" >&2
          exit 1
        fi
      done
    '';
    postInstall = ''
      mkdir -p "$out/bin"
      install -m 0755 kernel-fixtures/* "$out/bin/"
    '';
  };
in
  testing.mkVMTest {
    name = "sandbox-local-identity";
    rootfsDeps = [fixtures pkgs.coreutils pkgs.grep pkgs.util-linux];
    memory = 512;
    testScript = ''
      unset LD_LIBRARY_PATH
      mkdir -p /sys/fs/cgroup
      mount -t cgroup2 none /sys/fs/cgroup

      # A proper descendant exercises both exact and hinted membership. PID 1
      # stays at the hierarchy root; only this test shell and its children move.
      mkdir /sys/fs/cgroup/aos-local-identity-tests
      echo $$ > /sys/fs/cgroup/aos-local-identity-tests/cgroup.procs

      run_tests() {
        executable=$1
        filter=$2
        "$executable" --list "$filter" > /tmp/selected-tests
        if ! ${pkgs.grep}/bin/grep -q ': test$' /tmp/selected-tests; then
          echo "kernel qualification selected no tests: $executable $filter" >&2
          exit 1
        fi
        "$executable" "$filter" --test-threads=1 --nocapture
      }

      run_tests ${fixtures}/bin/aos_sandbox_linux cgroup::tests::real_readonly_hierarchy_resolves_exact_current_membership
      run_tests ${fixtures}/bin/aos_sandbox local_sessions::tests::
      run_tests ${fixtures}/bin/aos_sandbox local_provisioning::tests::
      run_tests ${fixtures}/bin/aos_sandbox publisher_sessions::kernel_tests::
      run_tests ${fixtures}/bin/aos_sandbox publisher_control::tests::
      run_tests ${fixtures}/bin/aos_sandbox journal::tests::failed_local_issuance_commit_never_activates_a_session
      run_tests ${fixtures}/bin/aos_sandbox journal::tests::failed_publisher_registration_commit_retires_execution_pin
      run_tests ${fixtures}/bin/aos_sandbox_host peer::tests::unregistered_controller_path_rejects_a_live_socket_peer
      run_tests ${fixtures}/bin/aos_sandbox_host broker::tests::service_peer::stale_accepted_peer_is_nonfatal_and_next_connection_is_handled
      run_tests ${fixtures}/bin/aos_sandbox_mount broker::tests::service_peer::stale_accepted_peer_is_nonfatal_and_next_connection_is_handled
    '';
  }
