# External CLI controls of the actual normal service's published execution.
{
  pkgs,
  lib,
  service,
  campaign,
  attemptFile,
  clientAuthorityFile,
  clientCertificateFile,
  clientKeyFile,
  idempotencyKey,
}: let
  authenticatedArguments = lib.escapeShellArgs [
    "--format"
    "json"
    "--daemon"
    "https://${service.listenAddress}"
    "--daemon-ca"
    clientAuthorityFile
    "--daemon-cert"
    clientCertificateFile
    "--daemon-key"
    clientKeyFile
  ];
  campaignArguments = lib.escapeShellArgs [
    "--format"
    "json"
    "campaign"
    "--socket"
    service.socketPath
    "--principal"
    "operator"
  ];
in
  assert builtins.match "[0-9a-f]{64}" idempotencyKey != null; ''
    set -eu
    evidence=/tmp/normal-service-client
    ${pkgs.coreutils}/bin/mkdir -p "$evidence"

    campaign_query() {
      ${pkgs.crucible}/bin/crucible ${campaignArguments} "$@"
    }
    host_query() {
      ${pkgs.crucible}/bin/crucible ${authenticatedArguments} host \
        --daemon-epoch "$epoch" --owner "$owner" "$@"
    }
    node_query() {
      host_query --node "$node" --owner-generation "$owner_generation" \
        --arena-generation "$arena_generation" "$@"
    }

    attempt="$(${pkgs.coreutils}/bin/cat ${lib.escapeShellArg attemptFile})"
    campaign_query status ${lib.escapeShellArg campaign} > "$evidence/created.json"
    created_snapshot="$(${pkgs.jq}/bin/jq -er '.snapshot' "$evidence/created.json")"
    campaign_query budget ${lib.escapeShellArg campaign} --expected "$created_snapshot" \
      --command ${lib.escapeShellArg (builtins.concatStringsSep "" (builtins.genList (_: "61") 32))} \
      add 1 --proposals 1 > "$evidence/budget.json"
    campaign_query status ${lib.escapeShellArg campaign} > "$evidence/budgeted.json"
    budgeted_snapshot="$(${pkgs.jq}/bin/jq -er '.snapshot' "$evidence/budgeted.json")"
    campaign_query start ${lib.escapeShellArg campaign} --expected "$budgeted_snapshot" \
      --command ${lib.escapeShellArg (builtins.concatStringsSep "" (builtins.genList (_: "62") 32))} \
      > "$evidence/started.json"

    # The authenticated snapshot and runtime projection provide observations,
    # not new resource or execution authority. Refuse an absent/completed owner.
    while :; do
      ${pkgs.systemd}/bin/systemctl is-active --quiet crucible-campaign.service
      campaign_query status ${lib.escapeShellArg campaign} > "$evidence/campaign.json"
      snapshot="$(${pkgs.jq}/bin/jq -er '.snapshot' "$evidence/campaign.json")"
      if campaign_query explain-attempt ${lib.escapeShellArg campaign} \
        --snapshot "$snapshot" --attempt "$attempt" \
        > "$evidence/attempt.json" 2> "$evidence/attempt.err"; then
        phase="$(${pkgs.jq}/bin/jq -r '.runtime.phase // "pending"' "$evidence/attempt.json")"
        case "$phase" in
          running) break ;;
          pending) ;;
          *) cat "$evidence/attempt.json" >&2; exit 1 ;;
        esac
      else
        cat "$evidence/attempt.err" >> "$evidence/pending-errors.log"
        # Only absent initial admission is a pollable semantic state. Preserve
        # all other initiating errors instead of converting them to readiness.
        ${pkgs.grep}/bin/grep -Fq 'campaign was not found' "$evidence/attempt.err" || {
          cat "$evidence/attempt.err" >&2
          exit 1
        }
      fi
      ${pkgs.coreutils}/bin/sleep 0.05
    done
    epoch_short="$(${pkgs.jq}/bin/jq -er \
      '.operational | select(.availability == "observed") | .daemon_epoch | select(test("^[0-9a-f]{32}$"))' \
      "$evidence/campaign.json")"
    owner_short="$(${pkgs.jq}/bin/jq -er \
      '.runtime | select(.phase == "running") | .execution | select(test("^[0-9a-f]{32}$"))' \
      "$evidence/attempt.json")"
    epoch="00000000000000000000000000000000$epoch_short"
    owner="00000000000000000000000000000000$owner_short"

    # Missing client authentication must fail before a host request is sent.
    if ${pkgs.crucible}/bin/crucible --daemon https://${service.listenAddress} \
      host --daemon-epoch "$epoch" --owner "$owner" targets \
      > "$evidence/no-auth.out" 2> "$evidence/no-auth.err"; then
      echo 'unauthenticated normal host control succeeded' >&2
      exit 1
    fi
    ${pkgs.grep}/bin/grep -Fq \
      'host controls require authenticated --daemon-ca/--daemon-cert/--daemon-key' \
      "$evidence/no-auth.err"

    host_query targets --limit 32 > "$evidence/targets.json"
    ${pkgs.jq}/bin/jq -e --arg epoch "$epoch" --arg owner "$owner" \
      '.kind == "targets" and .daemon_epoch == $epoch and .owner == $owner and .next == null
       and ([.targets[] | select(.retained_template == false)] | length == 1)' \
      "$evidence/targets.json" > /dev/null
    ${pkgs.jq}/bin/jq -e '.targets[] | select(.retained_template == false)' \
      "$evidence/targets.json" > "$evidence/target.json"
    node="$(${pkgs.jq}/bin/jq -er '.node | select(test("^[0-9a-f]{64}$"))' "$evidence/target.json")"
    owner_generation="$(${pkgs.jq}/bin/jq -er \
      '.owner_generation | select(. > 0 and . < 9223372036854775807)' "$evidence/target.json")"
    arena_generation="$(${pkgs.jq}/bin/jq -er \
      '.arena_generation | select(. > 0)' "$evidence/target.json")"
    node_query capabilities > "$evidence/capabilities.json"
    ${pkgs.jq}/bin/jq -e \
      '.kind == "capabilities" and .dynamic_residency and .disk_oriented
       and .qualification.authenticated_pages and .qualification.fault_safe_progress
       and .qualification.bounded_execution_peak' "$evidence/capabilities.json" > /dev/null
    node_query status > "$evidence/before.json"

    # A stale incarnation must refuse without changing the live policy/history.
    stale_generation=$((owner_generation + 1))
    if host_query --node "$node" --owner-generation "$stale_generation" \
      --arena-generation "$arena_generation" status \
      > "$evidence/stale.out" 2> "$evidence/stale.err"; then
      echo 'stale normal host target succeeded' >&2
      exit 1
    fi
    ${pkgs.grep}/bin/grep -Fq 'host operational target is unavailable' "$evidence/stale.err"
    node_query status > "$evidence/after-stale.json"
    ${pkgs.jq}/bin/jq -e --slurpfile before "$evidence/before.json" \
      '.target == $before[0].target and .policy_revision == $before[0].policy_revision
       and .accepted_unique_update_count == $before[0].accepted_unique_update_count' \
      "$evidence/after-stale.json" > /dev/null

    revision="$(${pkgs.jq}/bin/jq -er '.policy_revision' "$evidence/after-stale.json")"
    node_query set --expected-revision "$revision" \
      --idempotency-key ${lib.escapeShellArg idempotencyKey} \
      --mode disk-oriented --resident-target-bytes 0 \
      > "$evidence/accepted.json" 2> "$evidence/accepted.err"
    ${pkgs.jq}/bin/jq -e \
      '.kind == "policy-update" and .disposition == "accepted"
       and .accepted_policy.mode == "disk-oriented" and .accepted_policy.resident_target_bytes == 0' \
      "$evidence/accepted.json" > /dev/null
    retry_bytes="$(${pkgs.sed}/bin/sed -n \
      's/^crucible: host request retry bytes: //p' "$evidence/accepted.err")"
    test -n "$retry_bytes"
    node_query retry --canonical-request "$retry_bytes" > "$evidence/replayed.json"
    ${pkgs.jq}/bin/jq -e --slurpfile accepted "$evidence/accepted.json" \
      '.disposition == "replayed" and .request_digest == $accepted[0].request_digest
       and .target == $accepted[0].target and .policy_revision == $accepted[0].policy_revision
       and .accepted_policy == $accepted[0].accepted_policy' "$evidence/replayed.json" > /dev/null
    node_query status > "$evidence/after.json"
    ${pkgs.jq}/bin/jq -e --slurpfile accepted "$evidence/accepted.json" \
      '.policy_revision == $accepted[0].policy_revision
       and (.measurements_available | type == "boolean")
       and (if .measurements_available then
         [.private_resident_bytes, .shared_resident_bytes_observed,
           .preserved_backing_bytes, .private_dirty_bytes,
           .writeback_pending_bytes]
         | all(.[]; type == "number" and . >= 0)
       else
         .private_resident_bytes == null
         and .shared_resident_bytes_observed == null
         and .preserved_backing_bytes == null
         and .private_dirty_bytes == null
         and .writeback_pending_bytes == null
       end)
       and .activity != null
       and (.resident_observation_at_cut == null
         or (.resident_observation_at_cut.current == false
           and .resident_observation_at_cut.completed_ns >= .resident_observation_at_cut.started_ns
           and .resident_observation_at_cut.covered_bytes > 0))' \
      "$evidence/after.json" > /dev/null

    # Unknown classifications stay null; a future qualified producer must
    # report all five numeric classifications when it declares availability.
    # A bounded observation at a prior cut and activity are separate evidence.
    # Complete physical measurements remain a required, unqualified gate; this
    # component also does not establish guest-state or cold-fault equivalence.
    echo normal_service_main_client_authenticated=true
    echo normal_service_stale_target_refused=true
    echo normal_service_policy_retry_same_request=true
    # Export only this actual authenticated status projection. A separate
    # registered gate rejects unavailable/null classifications from the same VM.
    measurements="$(${pkgs.jq}/bin/jq -c '{
      target, observation_sequence, policy_revision, reservation_revision,
      measurements_available, private_resident_bytes,
      shared_resident_bytes_observed, preserved_backing_bytes,
      private_dirty_bytes, writeback_pending_bytes
    }' "$evidence/after.json")"
    printf 'normal_service_physical_measurements=%s\n' "$measurements"
    echo normal_service_complete_measurement_gate=REQUIRED_UNQUALIFIED
    echo NORMAL_SERVICE_RAM_CONTROL_PASS
  ''
