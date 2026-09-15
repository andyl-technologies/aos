# Runs four named current Rust-plugin variants through guarded real-QEMU nodes.
{
  pkgs,
  lib,
  attrPath,
  campaignComposition ? null,
  testing ? import ../../lib/testing {inherit pkgs lib;},
}: let
  source = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = import ./_cargo-deps.nix {inherit pkgs lib;};
  guest = import ./_nginx-curl-http-200-guest.nix {inherit pkgs;};
  idleGuest = import ./phase2-qemu-live-plugin-quantum-guest.nix {inherit pkgs;};
  flight = pkgs.mkDerivation {
    pname = "crucible-production-rust-plugin-flight";
    version = "0";
    src = source;
    buildDeps = [
      pkgs.coreutils
      pkgs.jq
      pkgs.openssl
      pkgs.pkg-config
      pkgs.protobuf
      pkgs.rust
      pkgs.sed
    ];
    runtimeDeps = [pkgs.openssl];

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
        name = "build";
        script = ''
          set -eu
          export CARGO_HOME="$TMPDIR/cargo"
          mkdir -p "$CARGO_HOME" .cargo
          sed "s|@vendor@|${cargoDeps}|g" \
            "${cargoDeps}/.cargo/config.toml" > .cargo/config.toml
          cargo build --frozen --offline --release \
            --manifest-path crates/Cargo.toml \
            --target-dir "$TMPDIR/target" \
            -p crucible-qemu \
            --example crucible-qemu-production-plugin-flight
          cargo test --frozen --offline \
            --manifest-path crates/Cargo.toml \
            --target-dir "$TMPDIR/target" \
            -p crucible-qemu \
            --example crucible-qemu-production-plugin-flight
          cargo test --frozen --offline --release --no-run \
            --message-format=json-render-diagnostics \
            --manifest-path crates/Cargo.toml \
            --target-dir "$TMPDIR/target" \
            -p crucible-daemon --lib > "$TMPDIR/daemon-messages.jsonl"
          daemon_test=$(jq -r \
            'select(.reason == "compiler-artifact" and .target.name == "crucible_daemon" and .profile.test == true and .executable != null) | .executable' \
            "$TMPDIR/daemon-messages.jsonl")
          test -f "$daemon_test"
          mkdir -p "$out/bin"
          cp \
            "$TMPDIR/target/release/examples/crucible-qemu-production-plugin-flight" \
            "$out/bin/"
          cp "$daemon_test" "$out/bin/crucible-daemon-host-parallel-flight"
          mkdir -p "$out/share"
          cp tests/crucible/fixtures/e2e-determinism.scenario.toml "$out/share/"
        '';
      }
    ];
  };
  rootfsDeps = [
    flight
    guest
    idleGuest
    pkgs.qemu-crucible
    pkgs.crucible-qemu-plugin
    pkgs.linux
    pkgs.e2fsprogs
    pkgs.coreutils
    pkgs.util-linux
    pkgs.grep
  ];
  testScript = ''
    set -eu
    for option in CFS_BANDWIDTH QUOTA QFMT_V2 QUOTACTL; do
      grep -Fxq "CONFIG_$option=y" ${pkgs.linux}/boot/config-*
    done
    mkdir -p /sys/fs/cgroup
    if ! ${pkgs.util-linux}/bin/mountpoint -q /sys/fs/cgroup; then
      ${pkgs.util-linux}/bin/mount -t cgroup2 none /sys/fs/cgroup
    fi
    echo '+cpu +memory +pids' > /sys/fs/cgroup/cgroup.subtree_control
    mkdir -p /sys/fs/cgroup/crucible
    echo '+cpu +memory +pids' > /sys/fs/cgroup/crucible/cgroup.subtree_control

    truncate -s 8G /tmp/attempts.img
    ${pkgs.e2fsprogs}/sbin/mkfs.ext4 -F -O quota,project \
      -E quotatype=prjquota /tmp/attempts.img
    mkdir /tmp/attempts
    ${pkgs.util-linux}/bin/mount -o loop,prjquota \
      /tmp/attempts.img /tmp/attempts
    mkdir -m 700 /tmp/attempts/run

    result=/tmp/production-plugin-result
    runtime_trace=/tmp/production-reference-runtime-determinism.trace
    ${pkgs.coreutils}/bin/timeout -k 15 600 \
      ${flight}/bin/crucible-qemu-production-plugin-flight \
      ${pkgs.qemu-crucible}/bin/qemu-system-x86_64 \
      ${pkgs.crucible-qemu-plugin}/lib/libcrucible_qemu_plugin.so \
      ${pkgs.linux}/boot/vmlinuz-* \
      ${idleGuest}/initrd.img \
      ${pkgs.qemu-crucible}/share/qemu/bios-256k.bin \
      /sys/fs/cgroup/crucible /tmp/attempts/run "$runtime_trace" > "$result"
    test -f "$runtime_trace"
    test ! -L "$runtime_trace"
    test -s "$runtime_trace"
    runtime_trace_sha256=$(${pkgs.coreutils}/bin/sha256sum "$runtime_trace" | ${pkgs.coreutils}/bin/cut -d ' ' -f 1)
    printf 'hot_fork_runtime_trace_sha256=%s\n' "$runtime_trace_sha256" >> "$result"
    cat "$result"
    for evidence in \
      PASS \
      gate=gate:production-rust-plugin-flight \
      rust_plugin_loaded=true \
      diskless_multiboot_runs=4 \
      fingerprint_flight_variants=reference,host-preempted,translation-prefetch,translation-prefetch-host-preempted \
      vcpu_count=4 \
      rr_switch_quantum=4096 \
      sample_count=4 \
      sample_target_icounts=2000000,2000001,4000000,8000000 \
      sample_stream_restart_identical=true \
      on_demand_worker_acknowledgements=24 \
      on_demand_boundary_stream_bit_identical=true \
      instruction_exact_window_lower_icount=2000000 \
      instruction_exact_window_upper_icount=2000001 \
      instruction_exact_window_width=1 \
      instruction_exact_rr_successor=true \
      instruction_exact_state_projection_changed=true \
      instruction_exact_fingerprint_changed=true \
      instruction_exact_localization=one-instruction-window \
      bounded_scheduler_preemption_applied=true \
      pending_quantum_preemption_certified=true \
      scheduler_preemption_mailbox_decisions=2 \
      scheduler_vcpu_switch_applied=true \
      scheduler_interrupt_applied=true \
      readiness_setup_marker_authenticated=true \
      all_vcpus_halted_observed=true \
      exact_timer_deadline_observed=true \
      queued_idle_wake_reached_exact_deadline=true \
      actual_virtual_timer_fire_authenticated=true \
      idle_wake_stream_restart_identical=true \
      nonmain_timer_service_completed_before_hot_fork=true \
      hot_fork_template_draining=true \
      hot_fork_template_prepared=true \
      hot_fork_preparation_order=timer-service-complete,draining,prepared \
      component_failures=0 \
      per_vcpu_register_files_present=true \
      aggregate_icount_equals_target=true; do
      test "$(grep -Fxc "$evidence" "$result")" -eq 1
    done
    for numeric_evidence in \
      nonmain_timer_service_list \
      nonmain_timer_service_generation \
      nonmain_timer_service_request_sequence \
      nonmain_timer_service_complete_sequence \
      nonmain_timer_service_raw_icount \
      hot_fork_template_generation; do
      test "$(grep -Ec "^$numeric_evidence=[1-9][0-9]*$" "$result")" -eq 1
    done
    witness_value() {
      sed -n "s/^$1=//p" "$result"
    }
    lower_rr_vcpu=$(witness_value instruction_exact_lower_rr_vcpu)
    upper_rr_vcpu=$(witness_value instruction_exact_upper_rr_vcpu)
    lower_rr_position=$(witness_value instruction_exact_lower_rr_position)
    upper_rr_position=$(witness_value instruction_exact_upper_rr_position)
    state_projection=$(witness_value instruction_exact_owning_vcpu_state_projection)
    first_state_component=$(witness_value instruction_exact_first_differing_state_component)
    if test "$lower_rr_position" -lt 4095; then
      test "$upper_rr_vcpu" = "$lower_rr_vcpu"
      test "$upper_rr_position" -eq "$((lower_rr_position + 1))"
    else
      test "$upper_rr_vcpu" -eq "$(((lower_rr_vcpu + 1) % 4))"
      test "$upper_rr_position" -eq 0
    fi
    test "$state_projection" = "vcpu[$lower_rr_vcpu].register_digest"
    test -n "$first_state_component"
    test "$first_state_component" != sample_icount
    test "$first_state_component" != rr_current_vcpu
    test "$first_state_component" != rr_position_in_quantum
    witness_generation=$(witness_value timer_witness_generation)
    setup_marker_icount=$(witness_value readiness_setup_marker_icount)
    armed_deadline_ns=$(witness_value timer_witness_armed_deadline_ns)
    armed_deadline_logical=$(witness_value timer_witness_armed_deadline_logical_icount)
    icount_shift=$(witness_value timer_witness_icount_shift)
    icount_scale_ns=$(witness_value timer_witness_icount_scale_ns)
    armed_raw_icount=$(witness_value timer_witness_armed_raw_icount)
    fired_expire_ns=$(witness_value timer_witness_fired_expire_ns)
    fired_virtual_ns=$(witness_value timer_witness_fired_virtual_ns)
    fired_raw_icount=$(witness_value timer_witness_fired_raw_icount)
    published_wake=$(witness_value timer_witness_published_wake_logical_icount)
    post_wake=$(witness_value timer_witness_post_wake_logical_icount)
    witness_completed=$(witness_value timer_witness_completed)
    witness_reserved=$(witness_value timer_witness_reserved)
    timer_service_list=$(witness_value nonmain_timer_service_list)
    timer_service_generation=$(witness_value nonmain_timer_service_generation)
    timer_service_request_sequence=$(witness_value nonmain_timer_service_request_sequence)
    timer_service_complete_sequence=$(witness_value nonmain_timer_service_complete_sequence)
    timer_service_raw_icount=$(witness_value nonmain_timer_service_raw_icount)
    hot_fork_template_generation=$(witness_value hot_fork_template_generation)
    test -n "$witness_generation"
    test "$witness_generation" -gt 0
    test -n "$setup_marker_icount"
    test "$setup_marker_icount" -gt 0
    test -n "$armed_deadline_ns"
    test "$armed_deadline_ns" = "$fired_expire_ns"
    expected_target_ns=$((armed_deadline_logical << icount_shift))
    test "$fired_virtual_ns" = "$expected_target_ns"
    test "$armed_deadline_ns" -le "$fired_virtual_ns"
    rounding_delta=$((fired_virtual_ns - armed_deadline_ns))
    test "$rounding_delta" -lt "$icount_scale_ns"
    test "$armed_raw_icount" = "$fired_raw_icount"
    test "$armed_deadline_logical" = "$published_wake"
    test "$setup_marker_icount" -le "$armed_deadline_logical"
    test "$published_wake" = "$post_wake"
    test "$witness_completed" = 1
    test "$witness_reserved" = 0
    test "$timer_service_list" -gt 0
    test "$timer_service_generation" -gt 0
    test "$timer_service_request_sequence" -gt 0
    test "$timer_service_complete_sequence" -gt "$timer_service_request_sequence"
    test "$timer_service_raw_icount" = "$fired_raw_icount"
    test "$hot_fork_template_generation" -gt 0
    test "$(grep -Ec '^hot_fork_runtime_trace_sha256=[0-9a-f]{64}$' "$result")" -eq 1
    # This canonical flight fixes shift zero, so ceil conversion is exact.
    test "$icount_shift" = 0
    test "$armed_deadline_ns" = "$fired_virtual_ns"
    grep -Fxq 'translation_prefetch_default_off=true' "$result"
    grep -Fxq 'translation_prefetch_helper_started=true' "$result"
    grep -Eq '^translation_prefetch_requests=[1-9][0-9]*$' "$result"
    grep -Eq '^translation_prefetch_completions=[1-9][0-9]*$' "$result"
    grep -Fxq 'translation_prefetch_on_off_fingerprint_identical=true' "$result"
    grep -Fxq 'translation_prefetch_preempted_identity=true' "$result"
    for lane in host-serial host-parallel host-failure host-recovery; do
      mkdir "/sys/fs/cgroup/crucible/$lane"
      echo '+cpu +memory +pids' \
        > "/sys/fs/cgroup/crucible/$lane/cgroup.subtree_control"
      mkdir -m 700 "/tmp/attempts/run/$lane"
    done
    mkdir -m 700 /tmp/run-state /tmp/checkpoints
    for kernel in ${pkgs.linux}/boot/vmlinuz-*; do
      export CRUCIBLE_HOST_PARALLEL_KERNEL="$kernel"
    done
    export CRUCIBLE_HOST_PARALLEL_QEMU=${pkgs.qemu-crucible}/bin/qemu-system-x86_64
    export CRUCIBLE_HOST_PARALLEL_PLUGIN=${pkgs.crucible-qemu-plugin}/lib/libcrucible_qemu_plugin.so
    export CRUCIBLE_HOST_PARALLEL_ROOT=${guest}/root.ext4
    export CRUCIBLE_HOST_PARALLEL_SCENARIO=${flight}/share/e2e-determinism.scenario.toml
    export CRUCIBLE_HOST_PARALLEL_CGROUP=/sys/fs/cgroup/crucible
    export CRUCIBLE_HOST_PARALLEL_STORAGE=/tmp/attempts/run
    export CRUCIBLE_HOST_PARALLEL_RUN_STATE=/tmp/run-state
    export CRUCIBLE_HOST_PARALLEL_CHECKPOINTS=/tmp/checkpoints
    export CRUCIBLE_HOST_PARALLEL_UID=65534
    export CRUCIBLE_HOST_PARALLEL_GID=65534
    lifecycle_log=/tmp/production-lifecycle-host-parallel.log
    ${pkgs.coreutils}/bin/timeout -k 30 1800 \
      ${flight}/bin/crucible-daemon-host-parallel-flight \
      --ignored --exact \
      qemu_campaign_lifecycle::tests::host_parallel_native::production_lifecycle_host_parallel_rounds_are_canonical_and_recoverable \
      --nocapture > "$lifecycle_log" 2>&1
    cat "$lifecycle_log"
    grep -Fq 'test result: ok. 1 passed; 0 failed; 0 ignored;' "$lifecycle_log"
    for evidence in \
      PASS \
      production_vm_lifecycle_path=true \
      production_host_parallel_requested_runs=2 \
      production_host_parallel_maximum_workers=2 \
      production_host_parallel_realized_parallelism=2 \
      production_host_parallel_commit_order=curl,io-probe \
      production_host_parallel_state_identity=true \
      production_host_parallel_time_identity=true \
      production_host_parallel_canonical_log_identity=true \
      production_host_parallel_worker_count_absent_from_checkpoint=true \
      production_host_parallel_failure_healthy_peer_advanced=true \
      production_host_parallel_failure_logical_state_uncommitted=true \
      production_host_parallel_failure_retry_poisoned=true \
      production_host_parallel_authenticated_exact_recovery=true; do
      test "$(grep -Fxc "$evidence" "$lifecycle_log")" -eq 1
    done
    for evidence in \
      production_vm_lifecycle_path=true \
      production_host_parallel_requested_runs=2 \
      production_host_parallel_maximum_workers=2 \
      production_host_parallel_realized_parallelism=2 \
      production_host_parallel_commit_order=curl,io-probe \
      production_host_parallel_state_identity=true \
      production_host_parallel_time_identity=true \
      production_host_parallel_canonical_log_identity=true \
      production_host_parallel_worker_count_absent_from_checkpoint=true \
      production_host_parallel_failure_healthy_peer_advanced=true \
      production_host_parallel_failure_logical_state_uncommitted=true \
      production_host_parallel_failure_retry_poisoned=true \
      production_host_parallel_authenticated_exact_recovery=true; do
      grep -Fx "$evidence" "$lifecycle_log" >> "$result"
    done
    printf '%s\n' PRODUCTION_PLUGIN_RUNTIME_TRACE_BEGIN
    ${pkgs.coreutils}/bin/base64 "$runtime_trace"
    printf '%s\n' PRODUCTION_PLUGIN_RUNTIME_TRACE_END
    printf '%s\n' PRODUCTION_PLUGIN_RESULT_BEGIN
    cat "$result"
    printf '%s\n' PRODUCTION_PLUGIN_RESULT_END
    ${pkgs.util-linux}/bin/umount /tmp/attempts
    echo "check=${attrPath}"
  '';
  gate = testing.mkVMTest {
    name = "crucible-production-rust-plugin-flight";
    memory = 8192;
    inherit rootfsDeps testScript;
  };
  exposedGate =
    gate
    // {
      passthru =
        (gate.passthru or {})
        // {
          inherit flight guest idleGuest rootfsDeps testScript;
        };
    };
in
  if campaignComposition == null
  then exposedGate
  else
    import ./phase9-campaign-mode-production-rust-plugin-flight.nix {
      inherit pkgs lib testing;
      inherit (campaignComposition) mode system;
      productionGate = exposedGate;
    }
