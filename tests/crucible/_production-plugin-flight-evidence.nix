# Normalizes the accepted driver transcript and checks canonical plugin evidence.
# The caller owns execution, deadlines, storage and diagnostic selection.
{
  pkgs,
  lib,
  blockRecoveryNanos,
}: {
  traceSummaryScript = ''
    # Only the accepted native driver emits this bounded summary after its
    # quota-contained trace closes; extraction performs no guest execution.
    test "$(${pkgs.grep}/bin/grep -Fxc PRODUCTION_PLUGIN_REFERENCE_TRACE_SUMMARY_BEGIN "$flight_log")" -eq 1
    test "$(${pkgs.grep}/bin/grep -Fxc PRODUCTION_PLUGIN_REFERENCE_TRACE_SUMMARY_END "$flight_log")" -eq 1
    ${pkgs.gawk}/bin/awk '
      $0 == "PRODUCTION_PLUGIN_REFERENCE_TRACE_SUMMARY_BEGIN" { inside = 1; next }
      $0 == "PRODUCTION_PLUGIN_REFERENCE_TRACE_SUMMARY_END" { inside = 0; next }
      inside { print }
    ' "$flight_log" > "$runtime_trace"
  '';

  retainFlightResultScript = ''
    ${pkgs.grep}/bin/grep -Fq 'test result: ok. 1 passed; 0 failed; 0 ignored;' "$flight_log"
    cat "$flight_log"
    # Retain libtest diagnostics separately from deterministic assertion rows;
    # host elapsed time and test runner banners are not guest evidence.
    ${pkgs.gawk}/bin/awk '
      $0 == "PRODUCTION_PLUGIN_REFERENCE_TRACE_SUMMARY_BEGIN" { summary = 1; next }
      $0 == "PRODUCTION_PLUGIN_REFERENCE_TRACE_SUMMARY_END" { summary = 0; next }
      summary { next }
      { sub(/^test packaged_qemu_executor::tests::paging_native::plugin_flight::production_managed_plugin_flight_preserves_preemption_idle_trace_and_block_recovery \.\.\. /, "") }
      $0 == "PASS" || /^[a-z_][a-z0-9_]*=/ { print }
    ' "$flight_log" > "$result"
  '';

  # The enclosing script supplies the final line break at this insertion point.
  validateFlightResultScript = lib.removeSuffix "\n" ''
    test -f "$runtime_trace"
    test ! -L "$runtime_trace"
    test -s "$runtime_trace"
    ${pkgs.grep}/bin/grep -Fxq 'schema=crucible-runtime-trace-summary-v1' "$runtime_trace"
    test "$(${pkgs.grep}/bin/grep -Ec '^bytes=[1-9][0-9]*$' "$runtime_trace")" -eq 1
    runtime_trace_bytes=$(${pkgs.grep}/bin/grep -E '^bytes=[1-9][0-9]*$' "$runtime_trace" | ${pkgs.coreutils}/bin/cut -d = -f 2)
    test "$runtime_trace_bytes" -gt 0
    test "$runtime_trace_bytes" -le 268435456
    printf 'reference_runtime_trace_bytes=%s\n' "$runtime_trace_bytes" >> "$result"
    ${pkgs.grep}/bin/grep -Eq '^rows=[1-9][0-9]*$' "$runtime_trace"
    ${pkgs.grep}/bin/grep -Eq '^post_8m_rows=[1-9][0-9]*$' "$runtime_trace"
    ${pkgs.grep}/bin/grep -Eq '^post_8m_normalized_sha256=[0-9a-f]{64}$' "$runtime_trace"
    test "$(${pkgs.grep}/bin/grep -Ec '^raw_sha256=[0-9a-f]{64}$' "$runtime_trace")" -eq 1
    runtime_trace_sha256=$(${pkgs.grep}/bin/grep -E '^raw_sha256=[0-9a-f]{64}$' "$runtime_trace" | ${pkgs.coreutils}/bin/cut -d = -f 2)
    printf 'reference_runtime_trace_sha256=%s\n' "$runtime_trace_sha256" >> "$result"
    cat "$result"
    for evidence in \
      PASS \
      gate=gate:production-rust-plugin-flight \
      production_accepted_assignment=true \
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
    # The marker and deadline are logical picosecond ticks; raw icount is a
    # separate retired-instruction count and cannot be compared to the marker.
    test "$setup_marker_icount" -le "$armed_deadline_tick"
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
  '';
}
