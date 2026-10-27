# Observes the real Main worker; this client issues no native or Source role.
{
  pkgs,
  lib,
  service,
  attemptFile,
  kind,
}: let
  campaignArguments = lib.escapeShellArgs ["--format" "json" "campaign" "--socket" service.socketPath "--principal" "operator"];
  command = suffix: builtins.concatStringsSep "" (builtins.genList (_: suffix) 32);
in ''
  set -eu
  evidence=/tmp/normal-plugin-flight
  ${pkgs.coreutils}/bin/mkdir -p "$evidence"
  campaign_query() {
    ${service.package}/bin/crucible ${campaignArguments} "$@"
  }
  attempt="$(${pkgs.coreutils}/bin/cat ${lib.escapeShellArg attemptFile})"
  campaign_query status normal-ram > "$evidence/created.json"
  snapshot="$(${pkgs.jq}/bin/jq -er .snapshot "$evidence/created.json")"
  campaign_query budget normal-ram --expected "$snapshot" --command ${command "61"} \
    add 1 --proposals 1 > "$evidence/budget.json"
  campaign_query status normal-ram > "$evidence/budgeted.json"
  snapshot="$(${pkgs.jq}/bin/jq -er .snapshot "$evidence/budgeted.json")"
  campaign_query start normal-ram --expected "$snapshot" --command ${command "62"} > "$evidence/started.json"

  # The enclosing existing VM watchdog remains the final bound. Poll only
  # snapshot races and pre-admission absence; execution refusal is a failure.
  completed=false
  for observation in $(${pkgs.coreutils}/bin/seq 1 36000); do
    ${pkgs.systemd}/bin/systemctl is-active --quiet crucible-campaign.service
    campaign_query status normal-ram > "$evidence/status.json"
    snapshot="$(${pkgs.jq}/bin/jq -er .snapshot "$evidence/status.json")"
    if campaign_query explain-attempt normal-ram --snapshot "$snapshot" --attempt "$attempt" \
      > "$evidence/attempt.json" 2> "$evidence/attempt.err"; then
      phase="$(${pkgs.jq}/bin/jq -r '.runtime.phase // "pending"' "$evidence/attempt.json")"
      case "$phase" in
        canceled) completed=true; break ;;
        pending|running) ;;
        *) cat "$evidence/attempt.json" >&2; exit 1 ;;
      esac
    else
      if ! ${pkgs.grep}/bin/grep -Eq 'campaign was not found|campaign request used stale snapshot' "$evidence/attempt.err"; then
        cat "$evidence/attempt.err" >&2
        exit 1
      fi
    fi
    ${pkgs.coreutils}/bin/sleep 0.05
  done
  test "$completed" = true
  ${pkgs.systemd}/bin/journalctl --no-pager --output=cat -u crucible-campaign.service > "$evidence/worker.log"
  for required in gate=gate:production-rust-plugin-flight production_accepted_assignment=true; do
    test "$(${pkgs.grep}/bin/grep -Fxc "$required" "$evidence/worker.log")" -eq 1
  done
  ${lib.optionalString (kind == "four-vcpu") ''
    for required in \
      diskless_multiboot_runs=2 \
      fingerprint_flight_variants=reference,host-preempted \
      vcpu_count=4 \
      on_demand_boundary_stream_bit_identical=true \
      bounded_scheduler_preemption_applied=true \
      pending_quantum_preemption_certified=true \
      actual_virtual_timer_fire_authenticated=true \
      idle_wake_stream_restart_identical=true; do
      test "$(${pkgs.grep}/bin/grep -Fxc "$required" "$evidence/worker.log")" -eq 1
    done
  ''}
  ${lib.optionalString (kind == "block-recovery") ''
    for required in \
      block_recovery_hot_fork_subflight=true \
      block_recovery_write_completed=true \
      hot_fork_template_draining=true \
      hot_fork_template_prepared=true \
      hot_fork_preparation_order=block-recovery-settled,draining,prepared; do
      test "$(${pkgs.grep}/bin/grep -Fxc "$required" "$evidence/worker.log")" -eq 1
    done
  ''}
  cat "$evidence/worker.log"
  echo NORMAL_PLUGIN_FLIGHT_PASS
''
