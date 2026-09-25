# Public CLI composition flight; privileged setup stays in a disposable VM.
{
  pkgs,
  lib,
  guestChoice ? false,
  envoyNetwork ? false,
  hotForkFlight ? false,
  campaignMidpoint ? false,
  findingExactBundle ? false,
  findingSignalBundle ? false,
  findingForkWrite ? false,
  maintenanceTransfer ? false,
  policyTimeout ? false,
}: let
  source = import ../../pkgs/tools/crucible/_cargo-source.nix {inherit lib;};
  controllerArtifacts = pkgs.crucible-controller.passthru.cargoArtifacts;
  cargoDeps = pkgs.crucible-controller.passthru.cargoDeps;
  controllerArtifactContract = controllerArtifacts.passthru.cargoArtifactContract;
  campaignFlightFeatures = lib.optionalString (campaignMidpoint || findingExactBundle || findingSignalBundle || findingForkWrite) " --features packaged-midpoint-flight";
  campaignFlightBuildCommand = "test --frozen --offline --release --no-run -j$NIX_BUILD_CORES -p crucible-cli --test campaign_process --test campaign_store_process --bin crucible${campaignFlightFeatures}";
  campaignFlightArtifacts = pkgs.mkCargoArtifacts {
    pname = "crucible-packaged-campaign-flight-artifacts";
    version = "0";
    src = pkgs.mkCargoDummySource {
      srcRoot = ../../crates;
      name = "crucible-packaged-campaign-flight-dummy-source";
      cargoRoot = "crates";
    };

    inherit cargoDeps;
    cargoArtifacts = controllerArtifacts;
    cargoArtifactContract = controllerArtifactContract;
    cargoEnv = controllerArtifactContract.cargoEnv;
    cargoRoot = "crates";
    cargoBuildCommands = [campaignFlightBuildCommand];

    buildDeps = [pkgs.rust.dev pkgs.pkg-config pkgs.openssl pkgs.protobuf];
    runtimeDeps = [pkgs.openssl];
  };
  gateway = pkgs.crucible.passthru.debugGateway;
  flight = pkgs.mkCargoPackage {
    pname = "crucible-packaged-campaign-flight";
    version = "0";
    src = source;

    inherit cargoDeps;
    cargoArtifacts = campaignFlightArtifacts;
    cargoArtifactContract = controllerArtifactContract;
    cargoEnv = controllerArtifactContract.cargoEnv;
    cargoRoot = "crates";
    cargoBuildCommands = [campaignFlightBuildCommand];
    installBins = false;
    doCheck = false;

    buildDeps = [pkgs.rust.dev pkgs.pkg-config pkgs.openssl pkgs.protobuf];
    runtimeDeps = [pkgs.openssl];

    postInstall = ''
      artifacts="$NIX_BUILD_TOP/cargo-build-messages.jsonl"
      store_test_binary=$(jq -r 'select(.reason == "compiler-artifact" and .target.name == "campaign_store_process" and .executable != null) | .executable' "$artifacts")
      campaign_test_binary=$(jq -r 'select(.reason == "compiler-artifact" and .target.name == "campaign_process" and .executable != null) | .executable' "$artifacts")
      unit_test_binary=$(jq -r 'select(.reason == "compiler-artifact" and .target.name == "crucible" and .target.kind == ["bin"] and .profile.test == true and .executable != null) | .executable' "$artifacts")
      test -f "$store_test_binary"
      test -f "$campaign_test_binary"
      test -f "$unit_test_binary"

      mkdir -p "$out/bin"
      cp "$store_test_binary" "$out/bin/campaign-store-process-flight"
      cp "$campaign_test_binary" "$out/bin/campaign-process-flight"
      cp "$unit_test_binary" "$out/bin/crucible-unit-flight"
      cp target/release/crucible "$out/bin/crucible"

      # Genesis is captured before execution; the immutable blank disk still
      # follows the production store-path contract for guest assets.
      truncate -s 1M "$out/root.raw"
    '';

    passthru = {
      cargoArtifacts = campaignFlightArtifacts;
      cargoArtifactContract = controllerArtifactContract;
    };
  };
  deployment = builtins.toFile "campaign-executor.toml" ''
    schema = "crucible.campaign-packaged-executor"
    version = 2
    cgroup_root = "/sys/fs/cgroup/crucible"
    run_root = "/tmp/attempts/run"
    attempt_namespace = "packaged-flight"
    first_project_id = 30000
    project_id_count = ${
      if findingForkWrite || hotForkFlight
      then "2"
      else "1"
    }
    child_user_id = 65534
    child_group_id = 65534
    maximum_tasks = ${
      if envoyNetwork
      then "256"
      else "64"
    }
    maximum_inodes = ${
      if envoyNetwork
      then "65536"
      else "4096"
    }
    finish_timeout_ms = ${
      if envoyNetwork
      then "30000"
      else "15000"
    }
    maximum_slots = ${
      if findingForkWrite || hotForkFlight
      then "2"
      else "1"
    }
    maximum_vcpus = ${
      if envoyNetwork
      then "5"
      else "2"
    }
    maximum_resident_bytes = ${toString (
      if envoyNetwork
      then 6442450944
      else if guestChoice || hotForkFlight || campaignMidpoint || findingExactBundle || findingSignalBundle || findingForkWrite
      then 1073741824
      else 536870912
    )}
    maximum_disk_bytes = ${
      if envoyNetwork
      then "10737418240"
      else "2147483648"
    }
    maximum_execution_quanta = ${
      if envoyNetwork
      then "250000"
      else "10000"
    }
    maximum_checkpoint_bytes = ${
      if envoyNetwork
      then "4294967296"
      else "1073741824"
    }
    worker_count = 1
    host_architecture = "x86_64"
    qemu_profile = "deterministic-tcg-v1"

    [operations]
    listener_workers = 4
    pending_connections = 16
    requests_per_connection = 4096
    accept_poll_interval_ms = 10
    exchange_read_timeout_ms = 30000
    exchange_write_timeout_ms = 30000
    runtime_poll_interval_ms = 100
    planner_scan_limit = 1024
    planner_input_bytes = 16777216
    planner_fuel = 1025
    executor_scan_limit = 1024
    worker_slots_per_campaign = 1

    ${lib.optionalString (guestChoice || hotForkFlight) ''
      [guest_selectable_boundary_diagnostics]
      maximum_events = 256
    ''}
  '';
  choiceInitramfs = import ./phase4-packaged-campaign-choice-guest.nix {inherit pkgs;};
  networkChoiceInitramfs = import ./phase2-qemu-live-network-io-guest.nix {
    inherit pkgs;
    selectable = true;
    campaignFlight = true;
  };
  envoyNetworkRootImage = import ./_envoy-network-guest.nix {inherit pkgs;};
  testing = import ../../lib/testing {inherit pkgs lib;};
  vmTest = testing.mkVMTest {
    name =
      if policyTimeout
      then "crucible-packaged-campaign-policy-timeout"
      else if maintenanceTransfer
      then "crucible-campaign-exact-maintenance-transfer"
      else if hotForkFlight
      then "crucible-campaign-public-materialization-tiers"
      else if envoyNetwork
      then "crucible-campaign-envoy-network"
      else if guestChoice
      then "crucible-packaged-campaign-choice"
      else if findingForkWrite
      then "crucible-campaign-finding-fork-write"
      else if findingExactBundle
      then "crucible-campaign-finding-exact-bundle"
      else if findingSignalBundle
      then "crucible-campaign-finding-signal-bundle"
      else if campaignMidpoint
      then "crucible-campaign-midpoint-debug"
      else "crucible-packaged-campaign";
    memory =
      if envoyNetwork
      then 8192
      else if findingForkWrite || hotForkFlight
      then 3072
      else 2048;
    headlessVcpuCount =
      if envoyNetwork
      then 6
      else 1;
    # Five 512 MiB RAM and 512 MiB disk snapshots need at least 5 GiB for
    # baked genesis alone. Leave 16 GiB writable for staged checkpoints,
    # quota-backed attempts, and copy-on-write overhead on the ext4 rootfs.
    extraWritableMiB =
      if envoyNetwork
      then 16384
      else 0;
    rootfsDeps =
      [flight deployment gateway pkgs.qemu-crucible pkgs.crucible-qemu-plugin pkgs.linux pkgs.e2fsprogs pkgs.coreutils pkgs.util-linux pkgs.grep]
      ++ (lib.optional envoyNetwork envoyNetworkRootImage)
      ++ (lib.optional (findingExactBundle || findingSignalBundle || findingForkWrite) pkgs.crucible)
      ++ (
        if guestChoice || hotForkFlight
        then [networkChoiceInitramfs]
        else if campaignMidpoint || findingExactBundle || findingSignalBundle || findingForkWrite
        then [choiceInitramfs]
        else []
      );
    testScript = ''
      set -eu
      ${lib.optionalString envoyNetwork ''
        # The headless harness mounts /tmp as a RAM-sized tmpfs. Put the
        # five-guest checkpoint workspace on the already-sized ext4 rootfs.
        ${pkgs.util-linux}/bin/mount -o remount,rw /
        ${pkgs.util-linux}/bin/mount --bind /var/tmp /tmp
        chmod 1777 /tmp
        printf 'campaign-workspace-capacity='
        ${pkgs.coreutils}/bin/df -Pm /tmp | ${pkgs.coreutils}/bin/tail -n 1
      ''}
      setup_log=/tmp/campaign-host-setup.log
      : > "$setup_log"

      cleanup_attempt_mount() {
        ${pkgs.util-linux}/bin/umount /tmp/attempts > /dev/null 2>&1 || true
      }

      setup_failure() {
        status="$1"
        stage="$2"
        echo "campaign-host-setup-failed=$stage status=$status"
        ${pkgs.coreutils}/bin/head -n 200 "$setup_log"
        exit "$status"
      }

      setup_step() {
        stage="$1"
        shift
        echo "campaign-host-setup-stage=$stage" >> "$setup_log"
        "$@" >> "$setup_log" 2>&1 || setup_failure "$?" "$stage"
      }

      trap cleanup_attempt_mount EXIT HUP INT TERM
      setup_step cgroup-root mkdir -p /sys/fs/cgroup
      setup_step cgroup-mount ${pkgs.util-linux}/bin/mount -t cgroup2 none /sys/fs/cgroup
      echo 'campaign-host-setup-stage=cgroup-root-controllers' >> "$setup_log"
      echo '+cpu +memory +pids' > /sys/fs/cgroup/cgroup.subtree_control 2>> "$setup_log" \
        || setup_failure "$?" cgroup-root-controllers
      setup_step cgroup-owner mkdir /sys/fs/cgroup/crucible
      echo 'campaign-host-setup-stage=cgroup-owner-controllers' >> "$setup_log"
      echo '+cpu +memory +pids' > /sys/fs/cgroup/crucible/cgroup.subtree_control 2>> "$setup_log" \
        || setup_failure "$?" cgroup-owner-controllers
      setup_step quota-image truncate -s ${
        if envoyNetwork
        then "16G"
        else "4G"
      } /tmp/attempts.img
      setup_step quota-format ${pkgs.e2fsprogs}/sbin/mkfs.ext4 -F -O quota,project -E quotatype=prjquota /tmp/attempts.img
      setup_step quota-mountpoint mkdir /tmp/attempts
      setup_step quota-mount ${pkgs.util-linux}/bin/mount -o loop,prjquota /tmp/attempts.img /tmp/attempts
      setup_step run-directories mkdir -m 700 /tmp/attempts/run /tmp/run-state
      setup_step deployment install -m 600 ${deployment} /tmp/executor.toml
      echo 'campaign-host-setup-complete=true'
      ${pkgs.coreutils}/bin/head -n 200 "$setup_log"
      export CRUCIBLE_PROCESS_FLIGHT_BINARY=${flight}/bin/crucible
      ${lib.optionalString (findingExactBundle || findingSignalBundle || findingForkWrite) "export CRUCIBLE_EXACT_BUNDLE_BINARY=${pkgs.crucible}/bin/crucible"}
      export CRUCIBLE_FLIGHT_QEMU=${pkgs.qemu-crucible}/bin/qemu-system-x86_64
      export CRUCIBLE_FLIGHT_PLUGIN=${pkgs.crucible-qemu-plugin}/lib/libcrucible_qemu_plugin.so
      export CRUCIBLE_FLIGHT_DEPLOYMENT=/tmp/executor.toml
      export CRUCIBLE_FLIGHT_RUN_ROOT=/tmp/attempts/run
      export CRUCIBLE_DEBUG_GATEWAY=${gateway}/bin/crucible-debug-gateway
      for kernel in ${pkgs.linux}/boot/vmlinuz-*; do export CRUCIBLE_KERNEL="$kernel"; done
      export CRUCIBLE_ROOT_IMAGE=${
        if envoyNetwork
        then "${envoyNetworkRootImage}/root.ext4"
        else "${flight}/root.raw"
      }
      ${lib.optionalString (guestChoice || hotForkFlight || campaignMidpoint || findingExactBundle || findingSignalBundle || findingForkWrite || maintenanceTransfer) "export CRUCIBLE_INITRD=${choiceInitramfs}/initrd.img"}
      export CRUCIBLE_RUN_STATE_ROOT=/tmp/run-state
      export CRUCIBLE_NATIVE_GUEST_ARCHITECTURE=x86_64
      ${
        if policyTimeout
        then ''
          timeout_selector=packaged::public_packaged_executor_retains_policy_timeout_causal_evidence
          timeout_log=/tmp/campaign-policy-timeout.log
          if ! ${flight}/bin/campaign-store-process-flight --ignored --list \
            > /tmp/campaign-policy-timeout-list.log 2>&1; then
            cat /tmp/campaign-policy-timeout-list.log
            exit 1
          fi
          ${pkgs.grep}/bin/grep -Fqx \
            "$timeout_selector: test" /tmp/campaign-policy-timeout-list.log

          if ! ${pkgs.coreutils}/bin/timeout -k 5 900 \
            ${flight}/bin/campaign-store-process-flight --ignored --exact \
            "$timeout_selector" --nocapture > "$timeout_log" 2>&1; then
            cat "$timeout_log"
            exit 1
          fi
          cat "$timeout_log"
          ${pkgs.grep}/bin/grep -Fxq 'packaged_policy_timeout_observation_authenticated=true' "$timeout_log"
          ${pkgs.grep}/bin/grep -Fxq 'packaged_policy_timeout_marker_authenticated=true' "$timeout_log"
          ${pkgs.grep}/bin/grep -Fxq 'public_packaged_policy_timeout_causal_evidence=true' "$timeout_log"
          ${pkgs.grep}/bin/grep -Fq \
            'test result: ok. 1 passed; 0 failed; 0 ignored;' "$timeout_log"
          printf '%s\n' \
            'gate=gate:campaign-policy-timeout-real-qemu' \
            'proven=typed-policy-timeout,retained-causal-marker'
        ''
        else if maintenanceTransfer
        then ''
          maintenance_selector=packaged::guest_choice::maintenance_transfer::public_active_pause_restart_and_executable_transfer_rejects_incompatible_provenance
          if ! ${flight}/bin/campaign-store-process-flight --ignored --list \
            > /tmp/campaign-maintenance-transfer-list.log 2>&1; then
            cat /tmp/campaign-maintenance-transfer-list.log
            exit 1
          fi
          ${pkgs.grep}/bin/grep -Fqx \
            "$maintenance_selector: test" \
            /tmp/campaign-maintenance-transfer-list.log

          if ! ${pkgs.coreutils}/bin/timeout -k 5 900 \
            ${flight}/bin/campaign-store-process-flight --ignored --exact \
            "$maintenance_selector" --nocapture \
            > /tmp/campaign-maintenance-transfer.log 2>&1; then
            cat /tmp/campaign-maintenance-transfer.log
            exit 1
          fi
          cat /tmp/campaign-maintenance-transfer.log
          for evidence in \
            source_active_world_exact_pause_restart=true \
            source_exact_resume_progress=true \
            source_nested_qemu_stopped=true \
            recipient_executable_archive_authenticated=true \
            recipient_exact_pin_import_authenticated=true \
            recipient_campaign_resume=true \
            recipient_imported_attempt_running=true \
            recipient_nested_qemu_stopped=true \
            incompatible_provenance_rejected_before_guest=true \
            source_checkpoint_preserved=true
          do
            ${pkgs.grep}/bin/grep -Fxq "$evidence" /tmp/campaign-maintenance-transfer.log
          done
          ${pkgs.grep}/bin/grep -Fq \
            'test result: ok. 1 passed; 0 failed; 0 ignored;' \
            /tmp/campaign-maintenance-transfer.log
          printf '%s\n' \
            'gate=gate:campaign-exact-maintenance-transfer' \
            'tasks=T-CAM-5.8' \
            'tier=real-packaged-qemu'
        ''
        else if hotForkFlight
        then ''
          export CRUCIBLE_INITRD=${networkChoiceInitramfs}/initrd.img
          tier_selector=packaged::guest_choice::public_packaged_campaign_exercises_all_materialization_tiers
          tier_log=/tmp/campaign-materialization-tiers.log
          ${flight}/bin/campaign-store-process-flight --ignored --list \
            > /tmp/campaign-materialization-tiers-list.log 2>&1
          ${pkgs.grep}/bin/grep -Fqx \
            "$tier_selector: test" /tmp/campaign-materialization-tiers-list.log

          if ! ${pkgs.coreutils}/bin/timeout -k 5 1800 \
            ${flight}/bin/campaign-store-process-flight --ignored --exact \
            "$tier_selector" --nocapture > "$tier_log" 2>&1; then
            cat "$tier_log"
            exit 1
          fi
          cat "$tier_log"
          ${pkgs.grep}/bin/grep -Fxq \
            'public_packaged_materialization_tiers=hot-fork,thin-replay,exact-restore' "$tier_log"
          ${pkgs.grep}/bin/grep -Fq \
            'test result: ok. 1 passed; 0 failed; 0 ignored;' "$tier_log"
          printf '%s\n' 'gate=gate:campaign-public-materialization-tiers'
        ''
        else if envoyNetwork
        then ''
          envoy_selector=packaged::envoy_network::public_five_node_envoy_network_reaches_measured_failover
          envoy_log=/tmp/campaign-envoy-network.log
          ${flight}/bin/campaign-store-process-flight --ignored --list \
            > /tmp/campaign-envoy-network-list.log 2>&1
          ${pkgs.grep}/bin/grep -Fqx "$envoy_selector: test" \
            /tmp/campaign-envoy-network-list.log
          : > "$envoy_log"
          ${pkgs.coreutils}/bin/timeout -k 5 3600 \
            ${flight}/bin/campaign-store-process-flight --ignored --exact \
            "$envoy_selector" --nocapture > "$envoy_log" 2>&1 &
          envoy_test=$!
          ${pkgs.coreutils}/bin/timeout -k 5 3610 \
            ${pkgs.coreutils}/bin/tail --pid="$envoy_test" -n +1 -F "$envoy_log" \
            | ${pkgs.grep}/bin/grep --line-buffered '^CRUCIBLE-ENVOY-WAIT-V1 ' \
            || true
          if ! wait "$envoy_test"; then
            cat "$envoy_log"
            exit 1
          fi
          cat "$envoy_log"
          ${pkgs.grep}/bin/grep -Fxq \
            'envoy_five_node_failover_and_recovery_authenticated=true' "$envoy_log"
          ${pkgs.grep}/bin/grep -Fq \
            'test result: ok. 1 passed; 0 failed; 0 ignored;' "$envoy_log"
          printf '%s\n' 'gate=gate:campaign-envoy-network-five-vm'
        ''
        else if guestChoice
        then ''
          export CRUCIBLE_INITRD=${networkChoiceInitramfs}/initrd.img
          if ! ${flight}/bin/campaign-store-process-flight --ignored --list \
            > /tmp/guest-choice-flight-list.log 2>&1; then
            cat /tmp/guest-choice-flight-list.log
            exit 1
          fi
          cat /tmp/guest-choice-flight-list.log
          guest_choice_listed=$(${pkgs.grep}/bin/grep -Fxc \
            'packaged::guest_choice::public_guest_choices_survive_exact_checkpoint_and_daemon_restart: test' \
            /tmp/guest-choice-flight-list.log || true)
          if [ "$guest_choice_listed" -ne 1 ]; then
            echo 'typed-choice checkpoint selector must be listed exactly once'
            exit 1
          fi

          # One 300-second discovery and four 240-second replay waits fit this bound.
          if ! ${pkgs.coreutils}/bin/timeout -k 5 1800 \
            ${flight}/bin/campaign-store-process-flight --ignored --exact \
            packaged::guest_choice::public_guest_choices_survive_exact_checkpoint_and_daemon_restart \
            --nocapture > /tmp/guest-choice-flight.log 2>&1; then
            cat /tmp/guest-choice-flight.log
            exit 1
          fi

          boundary_log=/tmp/guest-choice-boundary.log
          boundary_source_log=/tmp/guest-choice-boundary-source.log
          boundary_replay_log=/tmp/guest-choice-boundary-replay.log
          ${pkgs.grep}/bin/grep \
            '^CRUCIBLE-GUEST-SELECTABLE-BOUNDARY-V1 ' /tmp/guest-choice-flight.log \
            > "$boundary_log" || true
          ${pkgs.grep}/bin/grep -F ' stage=source-discovery ' "$boundary_log" \
            > "$boundary_source_log" || true
          ${pkgs.grep}/bin/grep -F ' stage=replay ' "$boundary_log" \
            > "$boundary_replay_log" || true
          boundary_source_count=$(${pkgs.coreutils}/bin/wc -l < "$boundary_source_log")
          boundary_replay_count=$(${pkgs.coreutils}/bin/wc -l < "$boundary_replay_log")
          echo "guest_choice_boundary_source_lines=$boundary_source_count"
          echo "guest_choice_boundary_replay_lines=$boundary_replay_count"
          ${pkgs.coreutils}/bin/cat "$boundary_log"

          if [ "$boundary_source_count" -eq 0 ] || [ "$boundary_replay_count" -eq 0 ]; then
            echo 'guest-choice boundary diagnostics require both source-discovery and replay records'
            exit 1
          fi
          ${pkgs.grep}/bin/grep -Fxq 'guest_choice_discrete_and_integer=true' /tmp/guest-choice-flight.log
          ${pkgs.grep}/bin/grep -Fxq 'guest_choice_rendezvous_icount=250000000' /tmp/guest-choice-flight.log
          ${pkgs.grep}/bin/grep -Fxq 'guest_choice_negative_result=true' /tmp/guest-choice-flight.log
          ${pkgs.grep}/bin/grep -Fxq 'guest_choice_initial_qemu_fingerprint_enabled=true' /tmp/guest-choice-flight.log
          ${pkgs.grep}/bin/grep -Fxq 'guest_choice_restarted_qemu_fingerprint_enabled=true' /tmp/guest-choice-flight.log
          ${pkgs.grep}/bin/grep -Fxq 'guest_choice_pending_choice_identity_preserved=true' /tmp/guest-choice-flight.log
          ${pkgs.grep}/bin/grep -Fxq 'guest_choice_pending_choice_answered_after_restart=true' /tmp/guest-choice-flight.log
          ${pkgs.grep}/bin/grep -Fxq 'guest_choice_boundary_diagnostics=true' /tmp/guest-choice-flight.log
          ${pkgs.grep}/bin/grep -Fxq 'guest_choice_resume_source_exact=true' /tmp/guest-choice-flight.log
          ${pkgs.grep}/bin/grep -Fxq 'guest_choice_post_resume_progress=true' /tmp/guest-choice-flight.log
          ${pkgs.grep}/bin/grep -Fxq 'guest_choice_network_frame_observed=true' /tmp/guest-choice-flight.log
          ${pkgs.grep}/bin/grep -Fq \
            'test result: ok. 1 passed; 0 failed; 0 ignored;' \
            /tmp/guest-choice-flight.log
          printf '%s\n' \
            'gate=gate:typed-choice-product-checkpoint' \
            'proven=typed-guest-registration,fresh-qemu-restore'
          cat /tmp/guest-choice-flight.log
        ''
        else if findingForkWrite
        then ''
          fork_selector=finding_exact_vm::packaged_finding_bundle_fork_write_is_noncanonical
          fork_log=/tmp/campaign-finding-fork-write.log
          if ! ${pkgs.coreutils}/bin/timeout -k 5 900 \
            ${flight}/bin/campaign-store-process-flight --exact \
            "$fork_selector" --nocapture > "$fork_log" 2>&1; then
            cat "$fork_log"
            exit 1
          fi
          cat "$fork_log"
          ${pkgs.grep}/bin/grep -Fxq 'finding_bundle_fork_source_owner_absent=true' "$fork_log"
          ${pkgs.grep}/bin/grep -Fxq 'finding_bundle_two_live_packaged_qemu=true' "$fork_log"
          ${pkgs.grep}/bin/grep -Fxq 'finding_bundle_noncanonical_register_write=true' "$fork_log"
          ${pkgs.grep}/bin/grep -Fxq 'finding_bundle_canonical_checkpoint_and_bundle_unchanged=true' "$fork_log"
          ${pkgs.grep}/bin/grep -Fxq 'finding_bundle_fork_qemu_teardown=true' "$fork_log"
          ${pkgs.grep}/bin/grep -Fq 'test result: ok. 1 passed; 0 failed; 0 ignored;' "$fork_log"
          printf '%s\n' 'gate=gate:campaign-finding-fork-write'
        ''
        else if findingExactBundle
        then ''
          bundle_selector=finding_exact_vm::packaged_finding_bundle_replays_without_source_owner
          bundle_log=/tmp/campaign-finding-exact-bundle.log
          if ! ${pkgs.coreutils}/bin/timeout -k 5 900 \
            ${flight}/bin/campaign-store-process-flight --exact \
            "$bundle_selector" --nocapture > "$bundle_log" 2>&1; then
            cat "$bundle_log"
            exit 1
          fi
          cat "$bundle_log"
          ${pkgs.grep}/bin/grep -Fxq 'finding_bundle_fresh_process_exact_qemu=true' "$bundle_log"
          ${pkgs.grep}/bin/grep -Fxq 'finding_bundle_source_owner_absent=true' "$bundle_log"
          ${pkgs.grep}/bin/grep -Fxq 'finding_bundle_signature_and_terminal_reproduced=true' "$bundle_log"
          ${pkgs.grep}/bin/grep -Fxq 'finding_bundle_live_midpoint_read_only=true' "$bundle_log"
          ${pkgs.grep}/bin/grep -Fxq 'finding_bundle_mutation_rejected_and_checkpoint_unchanged=true' "$bundle_log"
          ${pkgs.grep}/bin/grep -Fxq 'finding_bundle_tamper_rejected=true' "$bundle_log"
          ${pkgs.grep}/bin/grep -Fq 'test result: ok. 1 passed; 0 failed; 0 ignored;' "$bundle_log"
          printf '%s\n' 'gate=gate:campaign-finding-exact-read-only'
        ''
        else if findingSignalBundle
        then ''
          signal_selector=finding_exact_vm::packaged_finding_bundle_retains_selected_fault_and_guest_response
          signal_log=/tmp/campaign-finding-signal-bundle.log
          if ! ${pkgs.coreutils}/bin/timeout -k 5 900 \
            ${flight}/bin/campaign-store-process-flight --exact \
            "$signal_selector" --nocapture > "$signal_log" 2>&1; then
            cat "$signal_log"
            exit 1
          fi
          cat "$signal_log"
          ${pkgs.grep}/bin/grep -Fxq 'finding_bundle_selected_fault_and_guest_response=true' "$signal_log"
          ${pkgs.grep}/bin/grep -Fxq 'finding_bundle_signal_archive_unchanged=true' "$signal_log"
          ${pkgs.grep}/bin/grep -Fq 'test result: ok. 1 passed; 0 failed; 0 ignored;' "$signal_log"
          printf '%s\n' 'gate=gate:campaign-finding-signal-bundle'
        ''
        else if campaignMidpoint
        then ''
          midpoint_selector=public_campaign_debug_opens_authenticated_finding_at_fast_midpoint
          midpoint_list=/tmp/campaign-midpoint-debug-list.log
          midpoint_log=/tmp/campaign-midpoint-debug.log
          if ! ${flight}/bin/campaign-store-process-flight --list > "$midpoint_list" 2>&1; then
            cat "$midpoint_list"
            exit 1
          fi
          cat "$midpoint_list"
          midpoint_listed=$(${pkgs.grep}/bin/grep -Fxc \
            "$midpoint_selector: test" "$midpoint_list" || true)
          if [ "$midpoint_listed" -ne 1 ]; then
            echo 'campaign midpoint selector must be listed exactly once and nonignored'
            exit 1
          fi

          # KVM reached the first finding replay after about 224 seconds;
          # this selector also performs independent minimization, verification,
          # exact debug, and GC after that point.
          if ! ${pkgs.coreutils}/bin/timeout -k 5 900 \
            ${flight}/bin/campaign-store-process-flight --exact \
            "$midpoint_selector" --nocapture > "$midpoint_log" 2>&1; then
            cat "$midpoint_log"
            exit 1
          fi
          cat "$midpoint_log"
          ${pkgs.grep}/bin/grep -Fxq 'public_finding_midpoint_debug=true' "$midpoint_log"
          ${pkgs.grep}/bin/grep -Fxq 'authenticated_exact_checkpoint=true' "$midpoint_log"
          ${pkgs.grep}/bin/grep -Fxq 'authenticated_replay_violation_boundary=true' "$midpoint_log"
          test "$(${pkgs.grep}/bin/grep -Ec '^authenticated_replay_causal_entries=[1-9][0-9]*$' "$midpoint_log" || true)" -eq 1
          test "$(${pkgs.grep}/bin/grep -Ec '^minimization_original_replay=crucible\.campaign\.finding-triage-replay@finding-triage-replay\.[0-9]+\.[0-9a-f]{64}$' "$midpoint_log" || true)" -eq 1
          test "$(${pkgs.grep}/bin/grep -Ec '^verification_original_replay=crucible\.campaign\.finding-triage-replay@finding-triage-replay\.[0-9]+\.[0-9a-f]{64}$' "$midpoint_log" || true)" -eq 1
          test "$(${pkgs.grep}/bin/grep -Fxc 'authenticated_replay_selection_sequence=fast,q7' "$midpoint_log" || true)" -eq 1
          test "$(${pkgs.grep}/bin/grep -Fxc 'authenticated_replay_marker=selected-fast-q7' "$midpoint_log" || true)" -eq 1
          ${pkgs.grep}/bin/grep -Fxq 'fast_midpoint_restore=true' "$midpoint_log"
          ${pkgs.grep}/bin/grep -Fxq 'read_only_rsp_safe_read=true' "$midpoint_log"
          ${pkgs.grep}/bin/grep -Eq '^read_only_rsp_stop_class=[TSWX]$' "$midpoint_log"
          ${pkgs.grep}/bin/grep -Eq '^authenticated_restore_bytes=[1-9][0-9]*$' "$midpoint_log"
          ${pkgs.grep}/bin/grep -Eq '^authenticated_checkpoint_candidates=([2-9]|[1-9][0-9]+)$' "$midpoint_log"
          ${pkgs.grep}/bin/grep -Fxq 'retry_session_identity_stable=true' "$midpoint_log"
          ${pkgs.grep}/bin/grep -Fxq 'campaign_finding_immutable=true' "$midpoint_log"
          ${pkgs.grep}/bin/grep -Fxq 'production_qemu=true' "$midpoint_log"
          ${pkgs.grep}/bin/grep -Fq \
            'test result: ok. 1 passed; 0 failed; 0 ignored;' "$midpoint_log"
          printf '%s\n' \
            'gate=gate:campaign-midpoint-debug' \
            'tasks=T-CAM-9.3'
        ''
        else ''
          if ! ${flight}/bin/campaign-process-flight --ignored --list \
            > /tmp/campaign-process-flight-list.log 2>&1; then
            cat /tmp/campaign-process-flight-list.log
            exit 1
          fi
          cat /tmp/campaign-process-flight-list.log
          production_replay_listed=$(${pkgs.grep}/bin/grep -Fxc \
            'campaign_run_production_qemu_exact_checkpoint_then_replay_matches: test' \
            /tmp/campaign-process-flight-list.log || true)
          interactive_replay_listed=$(${pkgs.grep}/bin/grep -Fxc \
            'interactive_session_captures_and_replays_exact_live_artifact: test' \
            /tmp/campaign-process-flight-list.log || true)
          if [ "$production_replay_listed" -ne 1 ] || [ "$interactive_replay_listed" -ne 1 ]; then
            echo 'campaign replay selectors must each be listed exactly once'
            exit 1
          fi

          if ! ${pkgs.coreutils}/bin/timeout -k 5 300 \
            ${flight}/bin/campaign-process-flight --ignored --exact \
            public_default_run_executes_through_an_authenticated_campaign \
            --nocapture > /tmp/campaign-default-run-flight.log 2>&1; then
            cat /tmp/campaign-default-run-flight.log
            exit 1
          fi
          cat /tmp/campaign-default-run-flight.log
          ${pkgs.grep}/bin/grep -Fxq \
            'campaign_default_run=true' \
            /tmp/campaign-default-run-flight.log
          if ! ${pkgs.coreutils}/bin/timeout -k 5 300 \
            ${flight}/bin/campaign-process-flight --ignored --exact \
            campaign_virtual_time_save_feeds_native_resume \
            --nocapture > /tmp/campaign-native-save-flight.log 2>&1; then
            cat /tmp/campaign-native-save-flight.log
            exit 1
          fi
          cat /tmp/campaign-native-save-flight.log
          ${pkgs.grep}/bin/grep -Fxq \
            'campaign_save_resume=true' \
            /tmp/campaign-native-save-flight.log
          if ! ${pkgs.coreutils}/bin/timeout -k 5 300 \
            ${flight}/bin/campaign-process-flight --ignored --exact \
            campaign_run_production_qemu_exact_checkpoint_then_replay_matches \
            --nocapture > /tmp/campaign-failure-replay-flight.log 2>&1; then
            cat /tmp/campaign-failure-replay-flight.log
            exit 1
          fi
          cat /tmp/campaign-failure-replay-flight.log
          ${pkgs.grep}/bin/grep -Fxq \
            'campaign_production_qemu_exact_checkpoint_replay=true' \
            /tmp/campaign-failure-replay-flight.log
          ${pkgs.grep}/bin/grep -Fq \
            'test result: ok. 1 passed; 0 failed; 0 ignored;' \
            /tmp/campaign-failure-replay-flight.log
          if ! ${pkgs.coreutils}/bin/timeout -k 5 300 \
            ${flight}/bin/campaign-process-flight --ignored --exact \
            interactive_session_captures_and_replays_exact_live_artifact \
            --nocapture > /tmp/interactive-capture-replay-flight.log 2>&1; then
            cat /tmp/interactive-capture-replay-flight.log
            exit 1
          fi
          cat /tmp/interactive-capture-replay-flight.log
          ${pkgs.grep}/bin/grep -Fxq \
            'interactive_packaged_capture_replay=true' \
            /tmp/interactive-capture-replay-flight.log
          ${pkgs.grep}/bin/grep -Fq \
            'test result: ok. 1 passed; 0 failed; 0 ignored;' \
            /tmp/interactive-capture-replay-flight.log
          if ! ${pkgs.coreutils}/bin/timeout -k 5 300 \
            ${flight}/bin/crucible-unit-flight --ignored --exact \
            cli_replay::tests::actual_session_run_artifact_replays_through_campaign_owner \
            --nocapture > /tmp/campaign-actual-session-replay-flight.log 2>&1; then
            cat /tmp/campaign-actual-session-replay-flight.log
            exit 1
          fi
          cat /tmp/campaign-actual-session-replay-flight.log
          ${pkgs.grep}/bin/grep -Fxq \
            'actual_session_campaign_replay=true' \
            /tmp/campaign-actual-session-replay-flight.log
          if ! ${pkgs.coreutils}/bin/timeout -k 5 60 \
            ${flight}/bin/campaign-process-flight --ignored --exact \
            guarded_campaign_rejects_insufficient_capacity_before_guest_launch \
            --nocapture > /tmp/campaign-capacity-refusal-flight.log 2>&1; then
            cat /tmp/campaign-capacity-refusal-flight.log
            exit 1
          fi
          cat /tmp/campaign-capacity-refusal-flight.log
          ${pkgs.grep}/bin/grep -Fxq \
            'campaign_guarded_prelaunch_capacity_refusal=true' \
            /tmp/campaign-capacity-refusal-flight.log
          ${pkgs.coreutils}/bin/timeout -k 5 300 \
            ${flight}/bin/campaign-store-process-flight --ignored --exact \
            packaged::public_packaged_executor_captures_genesis_and_restarts --nocapture
          ${pkgs.coreutils}/bin/timeout -k 5 300 \
            ${flight}/bin/campaign-store-process-flight --ignored --exact \
            packaged::public_packaged_executor_completes_initial_discovery --nocapture
          ${pkgs.coreutils}/bin/timeout -k 5 300 \
            ${flight}/bin/campaign-store-process-flight --ignored --exact \
            packaged::public_packaged_executor_completes_guest_quantum --nocapture
          ${pkgs.coreutils}/bin/timeout -k 5 300 \
            ${flight}/bin/campaign-store-process-flight --ignored --exact \
            packaged::public_packaged_executor_observes_exact_trigger_deadlines --nocapture
          ${pkgs.coreutils}/bin/timeout -k 5 300 \
            ${flight}/bin/campaign-store-process-flight --ignored --exact \
            packaged::public_packaged_executor_synchronizes_exact_time_across_vms --nocapture
          ${pkgs.coreutils}/bin/timeout -k 5 300 \
            ${flight}/bin/campaign-store-process-flight --ignored --exact \
            packaged::public_packaged_executor_observes_zero_and_early_logical_deadlines --nocapture
        ''
      }
      ${pkgs.util-linux}/bin/umount /tmp/attempts
      trap - EXIT HUP INT TERM
    '';
  };
in
  vmTest
  // {
    passthru =
      (vmTest.passthru or {})
      // {
        campaignFlight = flight;
      };
  }
