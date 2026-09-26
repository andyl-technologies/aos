# Runs two diskless comparator variants and one block-recovery hot-fork subflight.
{
  pkgs,
  lib,
  attrPath,
  campaignComposition ? null,
  testing ? import ../../lib/testing {inherit pkgs lib;},
}: let
  repoRoot = ../..;
  repoRootString = toString repoRoot;
  source = builtins.path {
    path = repoRoot;
    name = "crucible-production-rust-flight-src";
    # The suite retains its complete source. This package only compiles the
    # workspace, the fixture embedded by daemon tests, and the QMP schema.
    filter = path: _type: let
      pathString = toString path;
      base = baseNameOf path;
      crates = "${repoRootString}/crates";
      licenses = "${repoRootString}/LICENSES";
    in
      base
      != ".git"
      && base != "target"
      && base != "__pycache__"
      && !lib.hasSuffix ".pyc" base
      && (
        pathString
        == repoRootString
        || pathString == "${repoRootString}/LICENSE"
        || pathString == crates
        || lib.hasPrefix "${crates}/" pathString
        || pathString == licenses
        || lib.hasPrefix "${licenses}/" pathString
        || pathString == "${repoRootString}/docs"
        || pathString == "${repoRootString}/docs/rfcs"
        || pathString == "${repoRootString}/docs/rfcs/0020-crucible-campaigns"
        || pathString == "${repoRootString}/docs/rfcs/0020-crucible-campaigns/schema-registry.tsv"
        || pathString == "${repoRootString}/tests"
        || pathString == "${repoRootString}/tests/crucible"
        || pathString == "${repoRootString}/tests/crucible/fixtures"
        || pathString == "${repoRootString}/tests/crucible/fixtures/e2e-determinism.scenario.toml"
      );
  };
  cargoDeps = import ./_cargo-deps.nix {
    inherit pkgs lib;
    src = source;
  };
  guest = import ./_nginx-curl-http-200-guest.nix {inherit pkgs;};
  idleGuest = import ./phase2-qemu-live-plugin-quantum-guest.nix {inherit pkgs;};
  blockRecoveryNanos = 5000000000;
  blockGuest = import ./phase2-qemu-live-block-io-guest.nix {inherit pkgs;};
  flight = pkgs.mkDerivation {
    pname = "crucible-production-rust-plugin-flight";
    version = "0";
    LIBSQLITE3_SYS_USE_PKG_CONFIG = "1";
    src = source;
    buildDeps = [
      pkgs.coreutils
      pkgs.jq
      pkgs.openssl
      pkgs.pkg-config
      pkgs.protobuf
      pkgs.rust
      pkgs.sed

      pkgs.sqlite
    ];
    runtimeDeps = [pkgs.openssl pkgs.sqlite];

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
          test "$(${pkgs.grep}/bin/grep -Fxc '        .with_console_capture()' \
            crates/crucible-qemu/examples/crucible-qemu-production-plugin-flight.rs)" -eq 1
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
          cargo test --frozen --offline \
            --manifest-path crates/Cargo.toml \
            --target-dir "$TMPDIR/target" \
            -p crucible-qemu --lib \
            supervision::runtime_determinism_trace::tests
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
    blockGuest
    pkgs.qemu-crucible
    pkgs.crucible-qemu-plugin
    pkgs.linux
    pkgs.e2fsprogs
    pkgs.coreutils
    pkgs.util-linux
    pkgs.grep
  ];
  attemptHostSetupScript = ''
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
  '';
  productionFlightCommand = ''
    ${pkgs.coreutils}/bin/timeout -k 15 600 \
      ${flight}/bin/crucible-qemu-production-plugin-flight \
      ${pkgs.qemu-crucible}/bin/qemu-system-x86_64 \
      ${pkgs.crucible-qemu-plugin}/lib/libcrucible_qemu_plugin.so \
      ${pkgs.linux}/boot/vmlinuz-* \
      ${idleGuest}/initrd.img \
      ${blockGuest}/initrd.img \
      ${pkgs.qemu-crucible}/share/qemu/bios-256k.bin \
      /sys/fs/cgroup/crucible /tmp/attempts/run \
  '';
  testScript = ''
    set -eu
    for option in CFS_BANDWIDTH QUOTA QFMT_V2 QUOTACTL; do
      ${pkgs.grep}/bin/grep -Fxq "CONFIG_$option=y" ${pkgs.linux}/boot/config-*
    done
    ${attemptHostSetupScript}

    result=/tmp/production-plugin-result
    runtime_trace=/tmp/production-reference-runtime-determinism.trace
    ${productionFlightCommand} "$runtime_trace" > "$result"
    test -f "$runtime_trace"
    test ! -L "$runtime_trace"
    test -s "$runtime_trace"
    runtime_trace_sha256=$(${pkgs.coreutils}/bin/sha256sum "$runtime_trace" | ${pkgs.coreutils}/bin/cut -d ' ' -f 1)
    printf 'reference_runtime_trace_sha256=%s\n' "$runtime_trace_sha256" >> "$result"
    cat "$result"
    for evidence in \
      PASS \
      gate=gate:production-rust-plugin-flight \
      rust_plugin_loaded=true \
      diskless_multiboot_runs=2 \
      fingerprint_flight_variants=reference,host-preempted \
      vcpu_count=4 \
      rr_switch_quantum=4096 \
      sample_count=5 \
      sample_target_picoseconds=2000000,2000001,2000051,4000000,8000000 \
      sample_stream_restart_identical=true \
      on_demand_worker_acknowledgements=14 \
      on_demand_boundary_stream_bit_identical=true \
      instruction_exact_window_lower_picoseconds=2000001 \
      instruction_exact_window_upper_picoseconds=2000051 \
      instruction_exact_window_width_picoseconds=50 \
      fractional_phase_window_lower_picoseconds=2000000 \
      fractional_phase_window_upper_picoseconds=2000001 \
      fractional_phase_no_retirement=true \
      fractional_phase_timer_projection_changed=true \
      fractional_phase_fingerprint_changed=true \
      instruction_exact_raw_retirement_successor=true \
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
      block_recovery_hot_fork_subflight=true \
      block_recovery_nanos=${toString blockRecoveryNanos} \
      block_recovery_write_completed=true \
      hot_fork_template_draining=true \
      hot_fork_template_prepared=true \
      hot_fork_preparation_order=block-recovery-settled,draining,prepared \
      component_failures=0 \
      per_vcpu_register_files_present=true \
      sample_logical_picoseconds_equal_target=true; do
      test "$(${pkgs.grep}/bin/grep -Fxc "$evidence" "$result")" -eq 1
    done
    for numeric_evidence in \
      block_recovery_pause_logical_icount \
      block_recovery_pause_raw_icount \
      hot_fork_template_generation; do
      test "$(${pkgs.grep}/bin/grep -Ec "^$numeric_evidence=[1-9][0-9]*$" "$result")" -eq 1
    done
    test "$(${pkgs.grep}/bin/grep -Ec '^block_recovery_start_tick=[0-9]+$' "$result")" -eq 1
    witness_value() {
      ${pkgs.grep}/bin/grep -E "^$1=" "$result" \
        | ${pkgs.coreutils}/bin/cut -d = -f 2-
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
    armed_deadline_ps=$(witness_value timer_witness_armed_deadline_ps)
    armed_deadline_tick=$(witness_value timer_witness_armed_deadline_tick)
    ticks_per_instruction=$(witness_value timer_witness_ticks_per_instruction)
    retirement_step_ps=$(witness_value timer_witness_retirement_step_ps)
    armed_raw_icount=$(witness_value timer_witness_armed_raw_icount)
    fired_expire_ps=$(witness_value timer_witness_fired_expire_ps)
    fired_virtual_ps=$(witness_value timer_witness_fired_virtual_ps)
    fired_raw_icount=$(witness_value timer_witness_fired_raw_icount)
    published_wake=$(witness_value timer_witness_published_wake_tick)
    post_wake=$(witness_value timer_witness_post_wake_tick)
    witness_completed=$(witness_value timer_witness_completed)
    witness_reserved=$(witness_value timer_witness_reserved)
    block_recovery_start_tick=$(witness_value block_recovery_start_tick)
    block_recovery_pause_logical_icount=$(witness_value block_recovery_pause_logical_icount)
    block_recovery_pause_raw_icount=$(witness_value block_recovery_pause_raw_icount)
    hot_fork_template_generation=$(witness_value hot_fork_template_generation)
    test -n "$witness_generation"
    test "$witness_generation" -gt 0
    test -n "$setup_marker_icount"
    test "$setup_marker_icount" -gt 0
    test -n "$armed_deadline_ps"
    test "$armed_deadline_ps" = "$fired_expire_ps"
    expected_target_ps=$armed_deadline_tick
    test "$fired_virtual_ps" = "$expected_target_ps"
    test "$armed_deadline_ps" -le "$fired_virtual_ps"
    rounding_delta=$((fired_virtual_ps - armed_deadline_ps))
    test "$rounding_delta" -lt "$retirement_step_ps"
    test "$armed_raw_icount" = "$fired_raw_icount"
    test "$armed_deadline_tick" = "$published_wake"
    test "$setup_marker_icount" -le "$armed_raw_icount"
    test "$published_wake" = "$post_wake"
    test "$witness_completed" = 1
    test "$witness_reserved" = 0
    test "$block_recovery_pause_logical_icount" -gt 0
    test "$block_recovery_pause_raw_icount" -gt 0
    block_recovery_deadline_tick=$((block_recovery_start_tick + ${toString blockRecoveryNanos} * 1000))
    test "$block_recovery_pause_logical_icount" -ge "$block_recovery_deadline_tick"
    test "$hot_fork_template_generation" -gt 0
    test "$(${pkgs.grep}/bin/grep -Ec '^reference_runtime_trace_sha256=[0-9a-f]{64}$' "$result")" -eq 1
    # The exact picosecond clock retires one instruction per 50 ticks.
    test "$ticks_per_instruction" = 50
    for lane in \
      host-serial host-parallel host-failure host-recovery \
      host-replay-genesis host-replay-oracle; do
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
    set +e
    ${pkgs.coreutils}/bin/timeout -k 30 1800 \
      ${flight}/bin/crucible-daemon-host-parallel-flight \
      --ignored --exact \
      qemu_campaign_lifecycle::tests::host_parallel_native::production_lifecycle_host_parallel_rounds_are_canonical_and_recoverable \
      --nocapture > "$lifecycle_log" 2>&1
    lifecycle_status=$?
    set -e
    cat "$lifecycle_log"
    if test "$lifecycle_status" -ne 0; then
      exit "$lifecycle_status"
    fi
    ${pkgs.grep}/bin/grep -Fq \
      'test result: ok. 1 passed; 0 failed; 0 ignored;' "$lifecycle_log"
    # Libtest appends the first --nocapture line to the test-name prefix.
    test "$(${pkgs.grep}/bin/grep -Fxc \
      'test qemu_campaign_lifecycle::tests::host_parallel_native::production_lifecycle_host_parallel_rounds_are_canonical_and_recoverable ... PASS' \
      "$lifecycle_log")" -eq 1
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
      test "$(${pkgs.grep}/bin/grep -Fxc "$evidence" "$lifecycle_log")" -eq 1
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
      ${pkgs.grep}/bin/grep -Fx "$evidence" "$lifecycle_log" >> "$result"
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
  blockRecoveryTestScript = ''
    set -eu
    ${attemptHostSetupScript}

    result=/tmp/block-recovery-diagnostic-result
    set +e
    CRUCIBLE_PRODUCTION_PLUGIN_FLIGHT_BLOCK_RECOVERY_ONLY=1 \
      ${productionFlightCommand} /tmp/unused-reference-runtime-trace > "$result"
    flight_status=$?
    set -e

    cat "$result"
    ${pkgs.util-linux}/bin/umount /tmp/attempts
    if test "$flight_status" -ne 0; then
      exit "$flight_status"
    fi
    for evidence in \
      PASS \
      diagnostic_mode=block-recovery-only \
      block_recovery_hot_fork_subflight=true \
      block_recovery_nanos=${toString blockRecoveryNanos} \
      block_recovery_write_completed=true \
      hot_fork_template_draining=true \
      hot_fork_template_prepared=true \
      hot_fork_preparation_order=block-recovery-settled,draining,prepared; do
      test "$(${pkgs.grep}/bin/grep -Fxc "$evidence" "$result")" -eq 1
    done
    for numeric_evidence in \
      block_recovery_pause_logical_icount \
      block_recovery_pause_raw_icount \
      hot_fork_template_generation; do
      test "$(${pkgs.grep}/bin/grep -Ec "^$numeric_evidence=[1-9][0-9]*$" "$result")" -eq 1
    done
    test "$(${pkgs.grep}/bin/grep -Ec '^block_recovery_start_tick=[0-9]+$' "$result")" -eq 1
  '';
  gate = testing.mkVMTest {
    name = "crucible-production-rust-plugin-flight";
    memory = 8192;
    inherit rootfsDeps testScript;
  };
  blockRecoveryDiagnostic = testing.mkVMTest {
    name = "crucible-production-rust-plugin-block-recovery-diagnostic";
    memory = 8192;
    inherit rootfsDeps;
    testScript = blockRecoveryTestScript;
  };
  exposedGate =
    gate
    // {
      inherit blockRecoveryDiagnostic;
      passthru =
        (gate.passthru or {})
        // {
          inherit
            flight
            guest
            idleGuest
            blockGuest
            rootfsDeps
            testScript
            blockRecoveryDiagnostic
            blockRecoveryTestScript
            ;
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
