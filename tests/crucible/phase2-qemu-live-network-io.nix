{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase2.qemuLiveNetworkIo",
  taskIds ? ["T-PLUG-8" "T-PLUG-10" "T-PLUG-11"],
  openTaskIds ? [],
  busyCeiling ? "4000000000",
  # Exact restore resumes beyond 7.3 billion guest instructions. Keep enough
  # host-liveness margin for concurrent hermetic QEMU gates and the ordered
  # post-quantum control acknowledgement; this bound never participates in
  # guest scheduling or trace state, and successful runs return immediately.
  networkTimeoutSecs ? "600",
  secondRunSchedulerPreemption ? "1",
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = import ./_cargo-deps.nix {inherit pkgs lib;};
  networkInitramfs = import ./phase2-qemu-live-network-io-guest.nix {inherit pkgs;};
in
  pkgs.mkDerivation {
    pname = "crucible-phase2-qemu-live-network-io";
    version = "0";
    src = crucibleSrc;

    buildDeps = [
      pkgs.coreutils
      pkgs.crucible-fixtures
      pkgs.crucible-qemu-plugin
      pkgs.grep
      pkgs.qemu-crucible
      pkgs.rust
      pkgs.sed
    ];

    # The standard AOS kernel carries CONFIG_PACKET=y and CONFIG_VIRTIO_NET=y;
    # the gate uses that shipped fixture instead of a gate-only kernel variant.
    GUEST_KERNEL = builtins.toString pkgs.linux;
    GUEST_INITRD = "${networkInitramfs}/initrd.img";
    GUEST_FIRMWARE = "${pkgs.qemu-crucible}/share/qemu/bios-256k.bin";
    CRUCIBLE_NETWORK_IO_BUSY_CEILING = busyCeiling;
    CRUCIBLE_NETWORK_IO_TIMEOUT_SECS = networkTimeoutSecs;
    CRUCIBLE_NETWORK_IO_SECOND_RUN_SCHEDULER_PREEMPTION = secondRunSchedulerPreemption;
    TASK_IDS = builtins.concatStringsSep "," taskIds;
    OPEN_TASK_IDS = builtins.concatStringsSep "," openTaskIds;
    ATTR_PATH = attrPath;

    phases = [
      {
        name = "unpack";
        script = ''
          cp -R "$src" source
          chmod -R u+w source
          cd source
        '';
      }
      {
        name = "configure";
        script = ''
          export CARGO_HOME="$TMPDIR/cargo"
          if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
            cd source
          fi
          mkdir -p "$CARGO_HOME" .cargo
          if [ -f "${cargoDeps}/.cargo/config.toml" ]; then
            sed "s|@vendor@|${cargoDeps}|g" "${cargoDeps}/.cargo/config.toml" \
              > .cargo/config.toml
          else
            printf '[source.crates-io]\nreplace-with = "vendored-sources"\n\n[source.vendored-sources]\ndirectory = "${cargoDeps}"\n\n' \
              > .cargo/config.toml
          fi
        '';
      }
      {
        name = "run-live-network-io";
        script = ''
          set -eu
          if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
            cd source
          fi
          vmlinuz=$(ls "$GUEST_KERNEL"/boot/vmlinuz-* | head -1)
          test -n "$vmlinuz"
          kernel_config=$(ls "$GUEST_KERNEL"/boot/config-* | head -1)
          test -n "$kernel_config"
          grep -Fxq 'CONFIG_PACKET=y' "$kernel_config"
          grep -Fxq 'CONFIG_VIRTIO_NET=y' "$kernel_config"
          grep -Fxq 'guest_traffic_origin=guest-only' \
            ${networkInitramfs}/evidence.env
          grep -Fxq 'guest_interface=virtio-net-eth0' \
            ${networkInitramfs}/evidence.env
          grep -Fxq 'guest_receive_filter=eth0-non-outgoing' \
            ${networkInitramfs}/evidence.env
          grep -Fxq 'guest_reply_ack_binding=exact-router-source-and-guest-destination' \
            ${networkInitramfs}/evidence.env
          grep -Fxq 'guest_self_probe_acknowledgement=forbidden' \
            ${networkInitramfs}/evidence.env
          grep -Fxq 'multi_guest_tx_order=deterministic-node-mac-stagger' \
            ${networkInitramfs}/evidence.env

          scheduler_test_list="$TMPDIR/bounded-scheduler-preemption.tests"
          cargo test \
            --frozen \
            --offline \
            --target-dir "$TMPDIR/live-network-io-target" \
            --manifest-path crates/Cargo.toml \
            -p crucible-qemu \
            --lib \
            -- \
            --list > "$scheduler_test_list"
          for test_name in \
            asynchronous_preemption_completes_while_target_runs \
            controller_waits_for_pending_work_release \
            disabled_adversary_spawns_no_controller \
            dropping_controller_resumes_and_joins_stopped_target \
            exited_target_fails_after_pending_work_release \
            first_stop_rejects_an_already_completed_quantum \
            signal_failure_is_reported_and_joined \
            stop_observation_honors_timeout_without_a_state_change \
            watchdog_expiry_directly_resumes_stopped_target; do
            grep -Fxq \
              "bounded_scheduler_preemption::tests::$test_name: test" \
              "$scheduler_test_list"
          done
          cargo test \
            --frozen \
            --offline \
            --target-dir "$TMPDIR/live-network-io-target" \
            --manifest-path crates/Cargo.toml \
            -p crucible-qemu \
            --lib \
            bounded_scheduler_preemption::tests:: \
            -- \
            --test-threads=1
          grep -Fxq \
            'supervision::network_io_gate::tests::certification_rejects_ack_before_router_delivery_or_with_wrong_mac: test' \
            "$scheduler_test_list"
          cargo test \
            --frozen \
            --offline \
            --target-dir "$TMPDIR/live-network-io-target" \
            --manifest-path crates/Cargo.toml \
            -p crucible-qemu \
            --lib \
            supervision::network_io_gate::tests::certification_rejects_ack_before_router_delivery_or_with_wrong_mac \
            -- \
            --exact

          cargo build \
            --frozen \
            --offline \
            --target-dir "$TMPDIR/live-network-io-target" \
            --manifest-path crates/Cargo.toml \
            -p crucible-qemu \
            --example crucible-qemu-live-network-io
          cargo build \
            --frozen \
            --offline \
            --target-dir "$TMPDIR/live-network-io-target" \
            --manifest-path crates/Cargo.toml \
            -p crucible-api \
            --example crucible-qemu-live-world-network

          run_dir="$TMPDIR/live-network-io-run"
          mkdir -p "$run_dir"
          report="$TMPDIR/live-network-io.result"
          # Three real-QEMU runs cover reference, bounded preemption, and a
          # fresh-process retained-frame restore. The last must honor every
          # canonical 4M-icount retry boundary through guest boot, so the whole
          # gate receives a fixed wall bound independent of its per-operation
          # 600-second liveness budget.
          timeout -k 15 1190 \
            "$TMPDIR/live-network-io-target/debug/examples/crucible-qemu-live-network-io" \
            ${pkgs.qemu-crucible}/bin/qemu-system-x86_64 \
            ${pkgs.crucible-qemu-plugin}/lib/libcrucible_qemu_plugin.so \
            "$vmlinuz" \
            "$GUEST_FIRMWARE" \
            "$GUEST_INITRD" \
            "$run_dir" \
            > "$report"

          cat "$report"
          grep -Fxq PASS "$report"
          grep -Fxq 'gate=gate:live-network-io' "$report"
          grep -Fxq 'certification=guest-tx-router-reply-guest-rx-ack' "$report"
          grep -Fxq 'network_backend=hostless-qemu-hubport' "$report"
          grep -Fxq 'network_ring=SLOT_NET_ROUTER' "$report"
          grep -Fxq 'host_traffic_injector=false' "$report"
          grep -Eq '^probe_emit_icount=[1-9][0-9]*$' "$report"
          grep -Eq '^reply_delivery_icount=[1-9][0-9]*$' "$report"
          grep -Fxq 'reply_latency_icount=100000000' "$report"
          grep -Eq '^ack_emit_icount=[1-9][0-9]*$' "$report"
          grep -Fxq 'acknowledgement_seen=true' "$report"
          grep -Fxq \
            'guest_ack_causality=exact-router-source-destination-and-post-delivery' \
            "$report"
          grep -Fxq 'boot_backpressure_retained=true' "$report"
          grep -Fxq 'canonical_backpressure_retry_delivered=true' "$report"
          grep -Fxq 'backpressure_retry_icount=4000001' "$report"
          grep -Fxq 'backpressure_guest_acknowledgement_seen=true' "$report"
          grep -Fxq 'retained_frame_fresh_process_restored=true' "$report"
          grep -Fxq 'retained_frame_durable_envelope_restored=true' "$report"
          grep -Fxq 'retained_frame_first_retry_icount=4000001' "$report"
          grep -Fxq 'deterministic_under_scheduler_preemption=true' "$report"
          grep -Eq '^hostile_probe_emit_icount=[1-9][0-9]*$' "$report"
          grep -Eq '^absolute_probe_origin_equal=(true|false)$' "$report"
          grep -Eq '^hostile_acknowledgement_offset_icount=[1-9][0-9]*$' "$report"
          grep -Eq '^acknowledgement_offset_equal=(true|false)$' "$report"
          grep -Fxq 'determinism_scope=router-delivery-and-frame-order' "$report"
          grep -Fxq 'host_adversary=bounded-scheduler-preemption' "$report"
          grep -Fxq 'host_scheduler_preemption_count=6' "$report"
          grep -Fxq 'host_scheduler_preemption_pending_quantum=true' "$report"
          grep -Eq '^completion_owned_frames=[1-9][0-9]*$' "$report"
          grep -Fxq 'host_scheduler_preemption_requested_milliseconds=90' "$report"
          grep -Fxq 'delayed_reply_applied=false' "$report"
          grep -Fxq 'orderly_child_exit=true' "$report"

          world_report="$TMPDIR/live-world-network.result"
          world_run_dir="$TMPDIR/live-world-network-run"
          mkdir -p "$world_run_dir"
          root_image=${pkgs.crucible-fixtures}/share/crucible/fixtures/root/aos-minimal-root.ext4
          timeout -k 15 1190 \
            "$TMPDIR/live-network-io-target/debug/examples/crucible-qemu-live-world-network" \
            ${pkgs.qemu-crucible}/bin/qemu-system-x86_64 \
            ${pkgs.crucible-qemu-plugin}/lib/libcrucible_qemu_plugin.so \
            "$vmlinuz" \
            "$root_image" \
            "$GUEST_INITRD" \
            "$world_run_dir" \
            > "$world_report"

          cat "$world_report"
          grep -Fxq PASS "$world_report"
          grep -Fxq 'gate=gate:live-world-network' "$world_report"
          grep -Fxq 'backend=production-qemu-lifecycle' "$world_report"
          grep -Fxq 'topology=two-vm-hostless-world-link' "$world_report"
          grep -Eq '^network_decisions=[1-9][0-9]*$' "$world_report"
          grep -Eq '^delivered_frames=[1-9][0-9]*$' "$world_report"
          grep -Eq '^guest_acknowledgements=[1-9][0-9]*$' "$world_report"
          grep -Fxq 'search_branch=loss-fire' "$world_report"
          grep -Fxq 'branch_decisions_match=true' "$world_report"
          grep -Fxq 'exact_restore_next_quantum_match=true' "$world_report"
          grep -Eq '^checkpoint_continuation_quanta=([1-9]|1[0-6])$' "$world_report"
          grep -Eq '^checkpoint_packet_continuation=[1-9][0-9]*$' "$world_report"
          grep -Eq '^checkpoint_fault_decision_continuation=[1-9][0-9]*$' "$world_report"

          mkdir -p "$out"
          cp "$report" "$out/result"
          cp "$world_report" "$out/live-world-network.result"
          {
            printf 'attr_path=%s\n' "$ATTR_PATH"
            printf 'task_ids=%s\n' "$TASK_IDS"
            printf 'open_task_ids=%s\n' "$OPEN_TASK_IDS"
            printf 'scope=certifying-live-guest-network-plugin-ring-exchange\n'
            printf 'proven=guest-originated-tx,hostless-router-ring,exact-router-latency,completion-owned-frame-transfer,real-qemu-nic-backpressure,canonical-backpressure-retry,retained-frame-guest-ack,fresh-process-retained-frame-restore,bounded-network-rx-attempts,lossless-qemu-rx,router-source-bound-guest-ack,post-reply-ack-coordinate,frame-order-scheduler-preemption-invariance,pending-quantum-preemption-overlap,production-two-vm-world-route,production-live-search-branch,durable-exact-restore-next-quantum,post-checkpoint-packet-and-fault-continuation\n'
            printf 'kernel_packet_socket=built-in\n'
            printf 'kernel_virtio_net=built-in\n'
          } >> "$out/result"
        '';
      }
    ];
  }
