# shellcheck shell=sh

campaign_matrix_exact_field() {
  name="$1"
  result="$2"
  value=$(sed -n "s/^$name=//p" "$result")
  test -n "$value" || return 1
  test "$(printf '%s\n' "$value" | wc -l | tr -d ' ')" -eq 1 || return 1
  printf '%s' "$value"
}

authenticate_campaign_matrix_raw_result() {
  raw_result="$1"
  expected_gate="$2"
  expected_mode="$3"
  expected_configuration_identity="$4"
  expected_toplevel="$5"
  expected_executor="$6"

  test "$(grep -Fxc PASS "$raw_result")" -eq 1 || return 1
  test "$(grep -Fxc "gate=$expected_gate" "$raw_result")" -eq 1 || return 1

  raw_mode=$(campaign_matrix_exact_field campaign_mode "$raw_result") || return 1
  raw_configuration_identity=$(
    campaign_matrix_exact_field campaign_configuration_identity "$raw_result"
  ) || return 1
  raw_toplevel=$(campaign_matrix_exact_field campaign_toplevel "$raw_result") || return 1
  raw_executor=$(campaign_matrix_exact_field executor_derivation "$raw_result") || return 1

  test "$raw_mode" = "$expected_mode" || return 1
  test "$raw_configuration_identity" = "$expected_configuration_identity" || return 1
  test "$raw_toplevel" = "$expected_toplevel" || return 1
  test "$raw_executor" = "$expected_executor" || return 1
}

normalize_campaign_matrix_semantic_result() {
  gate="$1"
  bound_result="$2"
  destination="$3"

  if test "$gate" != gate:perf-bench; then
    cp "$bound_result" "$destination"
    return 0
  fi

  duration=$(campaign_matrix_exact_field metric_cold_launch_to_first_quantum_ns "$bound_result") \
    || return 1
  installs=$(campaign_matrix_exact_field metric_lazy_restore_missing_installs "$bound_result") \
    || return 1

  # These are host observations rather than modeled identities. The duration
  # cannot exceed the native test's 4,500-second original execution deadline;
  # the activity counter remains a canonical positive unsigned 64-bit value.
  printf '%s\n' "$duration" | grep -Eq '^[1-9][0-9]*$' || return 1
  test "${#duration}" -le 13 || return 1
  test "$duration" -le 4500000000000 || return 1
  printf '%s\n' "$installs" | awk '
    !/^[1-9][0-9]*$/ { exit 1 }
    length($0) > 20 { exit 1 }
    length($0) == 20 && "x" $0 > "x18446744073709551615" { exit 1 }
  ' || return 1

  grep -Ev \
    '^(metric_cold_launch_to_first_quantum_ns|metric_lazy_restore_missing_installs)=' \
    "$bound_result" > "$destination"
}

extract_campaign_matrix_raw_result() {
  transcript="$1"
  destination="$2"

  awk '
    /^CAMPAIGN_GATE_RESULT_BEGIN$/ {
      if (state != 0) exit 1
      state = 1
      next
    }
    /^CAMPAIGN_GATE_RESULT_END$/ {
      if (state != 1) exit 1
      state = 2
      next
    }
    state == 1 { print }
    END { if (state != 2) exit 1 }
  ' "$transcript" > "$destination"
}
