{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase2.qemuLiveFaultHardware",
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = import ./_cargo-deps.nix {inherit pkgs lib;};
  faultHardwareGuest = import ./phase2-qemu-fault-hardware-guest.nix {inherit pkgs;};
  variantCaseManifest = ./phase2-qemu-live-fault-hardware-cases.txt;
in
  pkgs.mkDerivation {
    pname = "crucible-phase2-qemu-live-fault-hardware";
    version = "0";
    src = crucibleSrc;

    buildDeps = [
      pkgs.coreutils
      pkgs.crucible-qemu-plugin
      pkgs.grep
      pkgs.qemu-crucible
      pkgs.rust
      pkgs.sed
    ];

    GUEST_KERNEL = builtins.toString pkgs.linux;
    GUEST_FIRMWARE = "${pkgs.qemu-crucible}/share/qemu/bios-256k.bin";
    GUEST_INITRD = "${faultHardwareGuest}/initrd.img";
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
          sed "s|@vendor@|${cargoDeps}|g" "${cargoDeps}/.cargo/config.toml" \
            > .cargo/config.toml
        '';
      }
      {
        name = "run-live-fault-hardware";
        script = ''
          set -eu
          if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
            cd source
          fi
          vmlinuz=$(ls "$GUEST_KERNEL"/boot/vmlinuz-* | head -1)
          test -n "$vmlinuz"

          grep -Fxq 'guest_format=diskless-linux-initramfs' \
            ${faultHardwareGuest}/evidence.env
          grep -Fxq 'guest_accelerator_transport=modern-virtio-pci-split-virtqueue' \
            ${faultHardwareGuest}/evidence.env
          grep -Fq '.with_fingerprint(QemuLaunchPluginSwitch::On)' \
            crates/crucible-qemu/examples/crucible-qemu-live-fault-hardware.rs
          grep -Fq 'post_fault_fingerprint == pre_fault_fingerprint' \
            crates/crucible-qemu/examples/crucible-qemu-live-fault-hardware.rs
          grep -Fq 'pre_fault_sample.ram_digest == post_fault_sample.ram_digest' \
            crates/crucible-qemu/examples/crucible-qemu-live-fault-hardware.rs
          grep -Fq 'let fault_pump_drained = self.pump_fault_commands(raw_icount)?;' \
            crates/crucible-qemu-plugin/src/runtime/live_callbacks.rs
          grep -Fq 'if fault_pump_drained {' \
            crates/crucible-qemu-plugin/src/runtime/live_callbacks.rs
          control_pump_line=$(grep -n 'Fault-result polling uses this same control wake' \
            crates/crucible-qemu-plugin/src/runtime/live_callbacks.rs | cut -d: -f1)
          control_capture_line=$(grep -n 'if boundary_requested && let Some(fingerprint)' \
            crates/crucible-qemu-plugin/src/runtime/live_callbacks.rs | cut -d: -f1)
          test "$control_pump_line" -lt "$control_capture_line"

          plugin_test_list="$TMPDIR/live-fault-hardware-plugin.tests"
          cargo test \
            --frozen \
            --offline \
            --target-dir "$TMPDIR/live-fault-hardware-target" \
            --manifest-path crates/Cargo.toml \
            -p crucible-qemu-plugin \
            --lib \
            -- \
            --list > "$plugin_test_list"
          grep -Fxq \
            'runtime::live_callbacks::tests::drained_control_boundary_pumps_fault_commands_before_fingerprint_and_ack: test' \
            "$plugin_test_list"
          cargo test \
            --frozen \
            --offline \
            --target-dir "$TMPDIR/live-fault-hardware-target" \
            --manifest-path crates/Cargo.toml \
            -p crucible-qemu-plugin \
            --lib \
            runtime::live_callbacks::tests::drained_control_boundary_pumps_fault_commands_before_fingerprint_and_ack \
            -- \
            --exact --include-ignored
          composed_clock_policy_test=fault_command::tests::clock_tests::clock_impulse_result_and_event_use_the_same_typed_evidence
          grep -Fxq "$composed_clock_policy_test: test" "$plugin_test_list"
          cargo test \
            --frozen \
            --offline \
            --target-dir "$TMPDIR/live-fault-hardware-target" \
            --manifest-path crates/Cargo.toml \
            -p crucible-qemu-plugin \
            --lib "$composed_clock_policy_test" \
            -- \
            --exact --include-ignored

          shmem_test_list="$TMPDIR/live-fault-hardware-shmem.tests"
          cargo test \
            --frozen \
            --offline \
            --target-dir "$TMPDIR/live-fault-hardware-target" \
            --manifest-path crates/Cargo.toml \
            -p crucible-shmem \
            --lib \
            -- \
            --list > "$shmem_test_list"
          clock_evidence_test=fault_clock_evidence::tests::every_clock_evidence_kind_round_trips_canonically
          grep -Fxq "$clock_evidence_test: test" "$shmem_test_list"
          cargo test \
            --frozen \
            --offline \
            --target-dir "$TMPDIR/live-fault-hardware-target" \
            --manifest-path crates/Cargo.toml \
            -p crucible-shmem \
            --lib "$clock_evidence_test" \
            -- \
            --exact --include-ignored

          qemu_test_list="$TMPDIR/live-fault-hardware-qemu.tests"
          cargo test \
            --frozen \
            --offline \
            --target-dir "$TMPDIR/live-fault-hardware-target" \
            --manifest-path crates/Cargo.toml \
            -p crucible-qemu \
            --lib \
            -- \
            --list > "$qemu_test_list"
          node_schema_test=fault_action_sink::node_payload::tests::every_typed_node_effect_translates_to_its_closed_wire_schema
          typed_rejection_test=fault_action_sink::tests::authenticated_typed_prepare_rejection_is_not_a_fatal_commit_error
          grep -Fxq "$node_schema_test: test" "$qemu_test_list"
          grep -Fxq "$typed_rejection_test: test" "$qemu_test_list"
          cargo test \
            --frozen \
            --offline \
            --target-dir "$TMPDIR/live-fault-hardware-target" \
            --manifest-path crates/Cargo.toml \
            -p crucible-qemu \
            --lib "$node_schema_test" \
            -- \
            --exact --include-ignored
          cargo test \
            --frozen \
            --offline \
            --target-dir "$TMPDIR/live-fault-hardware-target" \
            --manifest-path crates/Cargo.toml \
            -p crucible-qemu \
            --lib "$typed_rejection_test" \
            -- \
            --exact --include-ignored

          matrix_plan_test=matrix_plan::tests::closed_hardware_variant_matrix_admits_every_exact_case
          cargo test \
            --frozen \
            --offline \
            --target-dir "$TMPDIR/live-fault-hardware-target" \
            --manifest-path crates/Cargo.toml \
            -p crucible-qemu \
            --example crucible-qemu-live-fault-hardware \
            -- \
            --list > "$TMPDIR/live-fault-hardware-example.tests"
          grep -Fxq "$matrix_plan_test: test" \
            "$TMPDIR/live-fault-hardware-example.tests"
          cargo test \
            --frozen \
            --offline \
            --target-dir "$TMPDIR/live-fault-hardware-target" \
            --manifest-path crates/Cargo.toml \
            -p crucible-qemu \
            --example crucible-qemu-live-fault-hardware \
            "$matrix_plan_test" \
            -- \
            --exact --include-ignored

          cargo build \
            --frozen \
            --offline \
            --target-dir "$TMPDIR/live-fault-hardware-target" \
            --manifest-path crates/Cargo.toml \
            -p crucible-qemu \
            --example crucible-qemu-live-fault-hardware

          run_dir="$TMPDIR/live-fault-hardware-run"
          mkdir -p "$run_dir"
          report="$TMPDIR/live-fault-hardware.result"
          timeout -k 15 590 \
            "$TMPDIR/live-fault-hardware-target/debug/examples/crucible-qemu-live-fault-hardware" \
            ${pkgs.qemu-crucible}/bin/qemu-system-x86_64 \
            ${pkgs.crucible-qemu-plugin}/lib/libcrucible_qemu_plugin.so \
            "$vmlinuz" \
            "$GUEST_FIRMWARE" \
            "$GUEST_INITRD" \
            "$run_dir" \
            > "$report"

          cat "$report"
          grep -Fxq PASS "$report"
          grep -Fxq 'gate=gate:live-fault-hardware' "$report"
          grep -Fxq 'guest_clock_reads=architecture-counter,posix-monotonic,posix-realtime' "$report"
          grep -Fxq 'accelerator_transport=real-modern-virtio-pci' "$report"
          grep -Fxq 'accelerator_jobs=gpu-vector-add,tpu-matrix-multiply,fpga-lookup-table' "$report"
          grep -Fxq 'accelerator_mutation=tpu-result-42-to-43' "$report"
          grep -Fxq 'host_adapter=qemu-live-accelerator-servicer' "$report"
          grep -Fxq 'boundary_signal_actions=6' "$report"
          grep -Fxq 'clock_signal_actions=1' "$report"
          grep -Fxq 'memory_signal_actions=1' "$report"
          grep -Fxq 'clock_source_signal_actions=1' "$report"
          grep -Fxq 'accelerator_lifecycle_signal_actions=1' "$report"
          grep -Fxq 'accelerator_memory_signal_actions=1' "$report"
          grep -Fxq 'accelerator_service_signal_actions=1' "$report"
          grep -Fxq 'same_icount_fault_fingerprint_changed=true' "$report"
          grep -Fxq 'same_icount_ram_fingerprint_changed=true' "$report"
          grep -Eq '^same_icount_fault_fingerprint_icount=[1-9][0-9]*$' "$report"
          grep -Fxq 'accelerator_signal_actions=1' "$report"
          grep -Fxq 'clock_occurrences=1' "$report"
          grep -Fxq 'accelerator_occurrences=1' "$report"
          grep -Fxq 'clock_source_occurrences=2' "$report"
          grep -Fxq 'accelerator_lifecycle_occurrences=1' "$report"
          grep -Fxq 'accelerator_memory_occurrences=1' "$report"
          grep -Fxq 'accelerator_service_occurrences=3' "$report"
          grep -Fxq 'fresh_plugin_restore=true' "$report"
          grep -Fxq 'orderly_child_exit=true' "$report"
          grep -Fxq 'typed_rejection_payload_authenticated=true' "$report"

          grep '^hardware_variant_case=' "$report" | cut -d= -f2- \
            > "$TMPDIR/hardware-variant-cases"
          test "$(wc -l < "$TMPDIR/hardware-variant-cases")" -eq 23
          test "$(sort -u "$TMPDIR/hardware-variant-cases" | wc -l)" -eq 23
          cmp ${variantCaseManifest} "$TMPDIR/hardware-variant-cases"
          grep -Fxq 'production_effect_row=clock.transform|offset-monotonic-overdue|gate:live-fault-hardware|production-qemu-signal-runtime|raw+transformed+timer-state' "$report"
          grep -Fxq 'production_effect_row=accelerator.result_transform|tpu-result-buffer-transform|gate:live-fault-hardware|production-qemu-signal-runtime|job-id+before-after-digest+guest-result' "$report"
          grep -Fxq 'production_effect_row=clock.source_state|degraded-step-synchronization|gate:live-fault-hardware|production-qemu-signal-runtime|old-new-source-state+timer-rearm' "$report"
          grep -Fxq 'production_effect_row=accelerator.lifecycle|reset-preserve-queues-and-memory|gate:live-fault-hardware|production-qemu-signal-runtime|enumeration+reset-generation+memory-digest' "$report"
          grep -Fxq 'production_effect_row=accelerator.memory_event|corrected-device-memory-ecc|gate:live-fault-hardware|production-qemu-signal-runtime|range+syndrome+corrected-counter+guest-results' "$report"
          grep -Fxq 'production_effect_row=accelerator.service|half-capacity-thermal-power|gate:live-fault-hardware|production-qemu-signal-runtime|three-job-service-ledger+thermal-power' "$report"

          mkdir -p "$out"
          cp "$report" "$out/result"
          printf 'attr_path=%s\n' "$ATTR_PATH" >> "$out/result"
          printf 'hardware_variant_matrix=23-exact-live-qemu-cases\n' >> "$out/result"
          printf 'hardware_variant_manifest=phase2-qemu-live-fault-hardware-cases.txt\n' >> "$out/result"
          printf 'proven=signal-driven-clock-mutation,signal-driven-clock-source-state,signal-driven-memory-mutation,same-icount-post-fault-fingerprint,same-icount-ram-digest-mutation,signal-driven-accelerator-lifecycle,signal-driven-accelerator-memory-event,signal-driven-accelerator-service,signal-driven-accelerator-result-mutation,authenticated-fault-occurrences,fresh-plugin-vmstate-reconstruction,real-linux-clock-observation,real-virtio-pci-discovery,guest-dma,split-virtqueue,gpu-job,tpu-job,fpga-job,fault-free-event-reservation,closed-clock-and-accelerator-variant-matrix\n' >> "$out/result"
        '';
      }
    ];
  }
