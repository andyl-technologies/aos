# Real cgroup-v2 qualification kept outside the hermetic package test sandbox.
{
  lib,
  testing,
  pkgs,
}: let
  packages = [
    "aos-sandbox"
    "aos-sandbox-broker-session-security"
    "aos-sandbox-linux"
    "aos-sandbox-host"
    "aos-sandbox-mount"
    "aos-sandbox-network"
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
    # Isolate subprocess fixtures from other tests' live journal descriptors.
    # Forked children can otherwise briefly retain another test's flock owner.
    cargoNextest = true;
    cargoTestFlags = "${packageFlags} --lib";
    installBins = false;
    buildDeps = [pkgs.protobuf];
    runtimeDeps = [];
    cargoEnv.PROTOC = "${pkgs.protobuf}/bin/protoc";
    # Preserve the feature-enabled executables before the check phase compiles
    # distinct default-feature test binaries into the same Cargo target tree.
    postBuild = ''
      mkdir kernel-fixtures
      for crate in aos_sandbox aos_sandbox_broker_session_security aos_sandbox_linux aos_sandbox_host aos_sandbox_mount aos_sandbox_network; do
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
    rootfsDeps = [fixtures pkgs.aos pkgs.aos-sandbox-mountd pkgs.coreutils pkgs.grep pkgs.util-linux];
    memory = 512;
    testScript = ''
      unset LD_LIBRARY_PATH
      mkdir -p /sys/fs/cgroup
      mount -t cgroup2 none /sys/fs/cgroup

      # A proper descendant exercises both exact and hinted membership. PID 1
      # stays at the hierarchy root; only this test shell and its children move.
      mkdir /sys/fs/cgroup/aos-local-identity-tests
      echo $$ > /sys/fs/cgroup/aos-local-identity-tests/cgroup.procs
      export AOS_CGROUP_TEST_SLEEP=${pkgs.coreutils}/bin/sleep
      export AOS_TEST_UNSHARE=${pkgs.util-linux}/bin/unshare
      # The minimal VM mounts /run with tmpfs's permissive default. Credential
      # custody requires the protected ancestor used by the installed service.
      chmod 0755 /run
      mkdir -p /run/aos/public-api-qualification
      chmod 0700 /run/aos/public-api-qualification
      chown 811:811 /run/aos/public-api-qualification
      mkdir -p /run/aos/sandboxd
      chmod 0755 /run/aos/sandboxd
      chown 811:811 /run/aos/sandboxd
      export AOS_PUBLIC_API_TEST_ROOT=/run/aos/public-api-qualification
      export AOS_PACKAGED_SANDBOX_CLI=${pkgs.aos}/bin/aos
      export AOS_BSA_QUALIFICATION_ROOT=/run/aos/broker-qualification

      # Stage fresh Controller-side trust after boot. Broker authority,
      # four-session reconciliation, and Host guest readiness remain separate
      # prerequisites before Create/RUNNING/Attach can be qualified.
      ${fixtures}/bin/aos_sandbox_broker_session_security \
        --ignored --list \
        handshake::qualification_credentials::provision_controller_broker_credentials_after_boot \
        > /tmp/broker-credential-tests
      ${pkgs.grep}/bin/grep -q ': test$' /tmp/broker-credential-tests
      ${fixtures}/bin/aos_sandbox_broker_session_security \
        --ignored --exact \
        handshake::qualification_credentials::provision_controller_broker_credentials_after_boot \
        --test-threads=1 --nocapture

      run_tests() {
        executable=$1
        filter=$2
        "$executable" --list "$filter" > /tmp/selected-tests
        if ! ${pkgs.grep}/bin/grep -q ': test$' /tmp/selected-tests; then
          echo "kernel qualification selected no tests: $executable $filter" >&2
          exit 1
        fi
        case "$filter" in
          controller_service::public_api::qualification_tests::*)
            ${pkgs.coreutils}/bin/chroot --userspec=+811:+811 --groups= / \
              "$executable" "$filter" --test-threads=1 --nocapture
            ;;
          broker::tests::host_scope_exchange::*)
            ${pkgs.util-linux}/bin/unshare --mount --propagation private \
              "$executable" "$filter" --test-threads=1 --nocapture
            ;;
          *) "$executable" "$filter" --test-threads=1 --nocapture ;;
        esac
      }

      run_tests ${fixtures}/bin/aos_sandbox_linux cgroup::tests::real_readonly_hierarchy_resolves_exact_current_membership
      run_tests ${fixtures}/bin/aos_sandbox_linux cgroup::tests::retained_population_distinguishes_empty_retired_and_recreated_cgroups
      run_tests ${fixtures}/bin/aos_sandbox_linux pidfd::tests::cross_uid_pidfd_liveness_does_not_require_signal_permission
      run_tests ${fixtures}/bin/aos_sandbox_linux seqpacket::descriptor_subject::tests::
      run_tests ${fixtures}/bin/aos_sandbox runtime_scope::kernel_tests::
      run_tests ${fixtures}/bin/aos_sandbox local_sessions::tests::
      run_tests ${fixtures}/bin/aos_sandbox local_provisioning::tests::
      run_tests ${fixtures}/bin/aos_sandbox publisher_sessions::kernel_tests::
      run_tests ${fixtures}/bin/aos_sandbox publisher_control::tests::
      run_tests ${fixtures}/bin/aos_sandbox journal::tests::failed_local_issuance_commit_never_activates_a_session
      run_tests ${fixtures}/bin/aos_sandbox journal::tests::failed_publisher_registration_commit_retires_execution_pin
      run_tests ${fixtures}/bin/aos_sandbox journal::tests::poisoned_journal_blocks_holder_join_despite_cached_live_state
      run_tests ${fixtures}/bin/aos_sandbox_host peer::tests::unregistered_controller_path_rejects_a_live_socket_peer
      cd /
      run_tests ${fixtures}/bin/aos_sandbox_host live_agent::argument_attempt::tests::
      run_tests ${fixtures}/bin/aos_sandbox_host broker::tests::service_peer::stale_accepted_peer_is_nonfatal_and_next_connection_is_handled
      run_tests ${fixtures}/bin/aos_sandbox_mount broker::tests::service_peer::stale_accepted_peer_is_nonfatal_and_next_connection_is_handled
      run_tests ${fixtures}/bin/aos_sandbox_mount broker::tests::host_scope_exchange::
      run_tests ${fixtures}/bin/aos_sandbox_network service::kernel_tests::controller_records_authenticated_netd_inventory_over_record_subject_session
      run_tests ${fixtures}/bin/aos_sandbox_broker_session_security controller_service::public_api::qualification_tests::registered_public_listener_uses_protected_credentials_and_real_http2
      run_tests ${fixtures}/bin/aos_sandbox_broker_session_security controller_service::public_api::qualification_tests::packaged_cli_uses_registered_public_transport

      # Same-named flattened and alternate branches are decoys. This focused
      # membership check accepts only the hierarchy implied by the slice name;
      # the installed-service fleet test separately proves systemd creates it.
      mkdir -p /sys/fs/cgroup/aos-control.slice/aos-sandboxd.service
      mkdir -p /sys/fs/cgroup/aos.slice/decoy.slice/aos-sandboxd.service
      mkdir -p /sys/fs/cgroup/aos-control.slice/aos-sandbox-mountd.service
      mkdir -p /sys/fs/cgroup/aos.slice/decoy.slice/aos-sandbox-mountd.service
      mkdir -p /sys/fs/cgroup/aos.slice/aos-control.slice/aos-sandboxd.service
      mkdir -p /sys/fs/cgroup/aos.slice/aos-control.slice/aos-sandbox-mountd.service

      echo $$ > /sys/fs/cgroup/aos.slice/aos-control.slice/aos-sandboxd.service/cgroup.procs
      run_tests ${fixtures}/bin/aos_sandbox_mount peer::tests::controller_path_rejects_flat_and_alternate_same_named_services

      echo $$ > /sys/fs/cgroup/aos.slice/aos-control.slice/aos-sandbox-mountd.service/cgroup.procs
      run_tests ${fixtures}/bin/aos_sandbox_host peer::tests::registered_root_mount_path_accepts_only_the_distinct_peer_profile

      # This one broker uses the same fixed custody roots and service cgroups
      # as the deployed units. The root-owned Mount journal and descriptor
      # worker serve real empty inventories through production dispatch.
      ${pkgs.coreutils}/bin/install -d -m 0755 /var/lib/aos
      ${pkgs.coreutils}/bin/install -d -o 811 -g 811 -m 0700 \
        /var/lib/aos/sandboxd /var/lib/aos/sandboxd/broker-session \
        /var/lib/aos/sandboxd/broker-session/mount \
        /var/lib/aos/sandboxd/broker-session/mount/custody
      ${pkgs.coreutils}/bin/install -d -m 0700 \
        /var/lib/aos/sandbox-mount /var/lib/aos/sandbox-mount/broker-session \
        /var/lib/aos/sandbox-mount/broker-session/custody \
        /run/aos/sandbox-mount-catalog
      for name in broker-session-manifest client-hello-signing-key client-record-signing-key; do
        ${pkgs.coreutils}/bin/install -o 811 -g 811 -m 0400 \
          /run/aos/broker-qualification/sessions/mount/client/$name \
          /var/lib/aos/sandboxd/broker-session/mount/custody/$name
      done
      for name in broker-session-manifest broker-hello-signing-key broker-outcome-signing-key; do
        ${pkgs.coreutils}/bin/install -m 0400 \
          /run/aos/broker-qualification/sessions/mount/broker/$name \
          /var/lib/aos/sandbox-mount/broker-session/custody/$name
      done
      chmod 0500 /var/lib/aos/sandboxd/broker-session/mount/custody
      chmod 0500 /var/lib/aos/sandbox-mount/broker-session/custody
      ${pkgs.coreutils}/bin/install -d -o 811 -g 811 -m 0700 /run/aos/controller-qualification
      ${pkgs.coreutils}/bin/install -o 811 -g 811 -m 0400 \
        /run/aos/broker-qualification/node-id /run/aos/controller-qualification/node-id
      ${pkgs.coreutils}/bin/install -d -o 0 -g 811 -m 0710 /run/aos/sandbox-mount
      export NOTIFY_SOCKET=@aos-mount-qualification
      export AOS_QUALIFICATION_MOUNT_HELPER=${pkgs.aos-sandbox-mountd}/bin/aos-sandbox-mount-helper
      export CREDENTIALS_DIRECTORY=/run/aos/broker-qualification/mount-authority

      for filter in \
        controller_service::qualification_mount_inventory::fixed_mount_inventory_broker \
        controller_service::qualification_mount_inventory::fixed_controller_mount_inventory_client; do
        ${fixtures}/bin/aos_sandbox_broker_session_security \
          --ignored --list "$filter" > /tmp/selected-mount-tests
        ${pkgs.grep}/bin/grep -q ': test$' /tmp/selected-mount-tests
      done

      ${fixtures}/bin/aos_sandbox_broker_session_security \
        --ignored --exact \
        controller_service::qualification_mount_inventory::fixed_mount_inventory_broker \
        --test-threads=1 --nocapture > /tmp/fixed-mount-inventory-broker.log 2>&1 &
      mount_broker_pid=$!
      for attempt in 1 2 3 4 5 6 7 8 9 10; do
        if [ -S /run/aos/sandbox-mount/control.sock ]; then break; fi
        if ! kill -0 "$mount_broker_pid"; then
          ${pkgs.coreutils}/bin/cat /tmp/fixed-mount-inventory-broker.log
          exit 1
        fi
        ${pkgs.coreutils}/bin/sleep 1
      done
      test -S /run/aos/sandbox-mount/control.sock
      chown 811:811 /run/aos/sandbox-mount/control.sock
      chmod 0600 /run/aos/sandbox-mount/control.sock

      echo $$ > /sys/fs/cgroup/aos.slice/aos-control.slice/aos-sandboxd.service/cgroup.procs
      export CREDENTIALS_DIRECTORY=/run/aos/controller-qualification
      if ! ${pkgs.coreutils}/bin/chroot --userspec=+811:+811 --groups= / \
        ${fixtures}/bin/aos_sandbox_broker_session_security \
          --ignored --exact \
          controller_service::qualification_mount_inventory::fixed_controller_mount_inventory_client \
          --test-threads=1 --nocapture; then
        ${pkgs.coreutils}/bin/cat /tmp/fixed-mount-inventory-broker.log
        exit 1
      fi
      wait "$mount_broker_pid" || {
        ${pkgs.coreutils}/bin/cat /tmp/fixed-mount-inventory-broker.log
        exit 1
      }
      ${pkgs.grep}/bin/grep -q FIXED_MOUNT_BROKER_INVENTORY_PASS /tmp/fixed-mount-inventory-broker.log

      # Host retains its three fixed audience listeners, but this qualification
      # sends only the Controller's read-only runtime Inventory method. No
      # runtime effect, Host attach method, or guest-readiness path is entered.
      mkdir -p /sys/fs/cgroup/aos.slice/aos-control.slice/aos-sandbox-hostd.service
      ${pkgs.coreutils}/bin/install -d -o 811 -g 811 -m 0700 \
        /var/lib/aos/sandboxd/broker-session/host \
        /var/lib/aos/sandboxd/broker-session/host/custody
      ${pkgs.coreutils}/bin/install -d -m 0700 \
        /var/lib/aos/sandbox-host \
        /var/lib/aos/sandbox-host/broker-session \
        /var/lib/aos/sandbox-host/broker-session/controller \
        /var/lib/aos/sandbox-host/broker-session/controller/custody
      for name in broker-session-manifest client-hello-signing-key client-record-signing-key; do
        ${pkgs.coreutils}/bin/install -o 811 -g 811 -m 0400 \
          /run/aos/broker-qualification/sessions/host/client/$name \
          /var/lib/aos/sandboxd/broker-session/host/custody/$name
      done
      for name in broker-session-manifest broker-hello-signing-key broker-outcome-signing-key; do
        ${pkgs.coreutils}/bin/install -m 0400 \
          /run/aos/broker-qualification/sessions/host/broker/$name \
          /var/lib/aos/sandbox-host/broker-session/controller/custody/$name
      done
      chmod 0500 /var/lib/aos/sandboxd/broker-session/host/custody
      chmod 0500 /var/lib/aos/sandbox-host/broker-session/controller/custody
      ${pkgs.coreutils}/bin/install -d -o 0 -g 811 -m 0710 /run/aos/sandbox-host

      for filter in \
        controller_service::qualification_host_inventory::fixed_host_inventory_broker \
        controller_service::qualification_host_inventory::fixed_controller_host_inventory_client; do
        ${fixtures}/bin/aos_sandbox_broker_session_security \
          --ignored --list "$filter" > /tmp/selected-host-tests
        ${pkgs.grep}/bin/grep -q ': test$' /tmp/selected-host-tests
      done

      echo $$ > /sys/fs/cgroup/aos.slice/aos-control.slice/aos-sandbox-hostd.service/cgroup.procs
      export CREDENTIALS_DIRECTORY=/run/aos/broker-qualification/host-authority
      ${fixtures}/bin/aos_sandbox_broker_session_security \
        --ignored --exact \
        controller_service::qualification_host_inventory::fixed_host_inventory_broker \
        --test-threads=1 --nocapture > /tmp/fixed-host-inventory-broker.log 2>&1 &
      host_broker_pid=$!
      for attempt in 1 2 3 4 5 6 7 8 9 10; do
        if [ -S /run/aos/sandbox-host/control.sock ]; then break; fi
        if ! kill -0 "$host_broker_pid"; then
          ${pkgs.coreutils}/bin/cat /tmp/fixed-host-inventory-broker.log
          exit 1
        fi
        ${pkgs.coreutils}/bin/sleep 1
      done
      test -S /run/aos/sandbox-host/control.sock
      test -S /run/aos/sandbox-host/root-mount.sock
      test -S /run/aos/sandbox-host/storage.sock
      chown 811:811 /run/aos/sandbox-host/control.sock
      chmod 0600 /run/aos/sandbox-host/control.sock

      echo $$ > /sys/fs/cgroup/aos.slice/aos-control.slice/aos-sandboxd.service/cgroup.procs
      export CREDENTIALS_DIRECTORY=/run/aos/controller-qualification
      if ! ${pkgs.coreutils}/bin/chroot --userspec=+811:+811 --groups= / \
        ${fixtures}/bin/aos_sandbox_broker_session_security \
          --ignored --exact \
          controller_service::qualification_host_inventory::fixed_controller_host_inventory_client \
          --test-threads=1 --nocapture; then
        ${pkgs.coreutils}/bin/cat /tmp/fixed-host-inventory-broker.log
        exit 1
      fi
      wait "$host_broker_pid" || {
        ${pkgs.coreutils}/bin/cat /tmp/fixed-host-inventory-broker.log
        exit 1
      }
      ${pkgs.grep}/bin/grep -q FIXED_HOST_BROKER_INVENTORY_PASS /tmp/fixed-host-inventory-broker.log
    '';
  }
