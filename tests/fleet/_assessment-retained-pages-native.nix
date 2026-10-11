# Source-built test transport with real database custody and the packaged CLI.
{pkgs}: let
  native = pkgs.aos-hub;
  # Core's Hybrid tests include Worker source by path. The serving slice omits
  # those test-only files; retain the established integration-test source.
  source = pkgs.aos.passthru.testTargets.src;
  vendor = builtins.elemAt native.passthru.evidenceSources 1;
  selector = "db::assessment::read_snapshot_tests::actual_cli_retains_scan_pages_across_database_reopen";
  subscriptionSelector = "db::assessment::subscription_snapshot::tests::actual_cli_retains_subscription_pages_across_database_reopen";
  alertSelector = "db::assessment::alert_snapshot::tests::actual_cli_retains_alert_revisions_across_database_reopen";
  scheduleSelector = "db::assessment::schedule_snapshot::tests::actual_cli_retains_schedule_reviews_across_database_reopen";
  deliverySelector = "db::assessment::delivery_snapshot::tests::actual_cli_retains_delivery_attempts_across_database_reopen";
  serviceSelector = "db::assessment::schedules::service_tests::actual_cli_reads_service_review_after_database_reopen";
  serviceRevocationSelector = "db::assessment::schedules::service_tests::service_scan_rechecks_exact_credential_after_reviewing_session_ends";
  notificationServiceSelector = "db::assessment::notifications::service_tests::service_delivery_survives_reviewer_revocation_and_refuses_revoked_service_receipts";
  scheduleQueueSelector = "db::assessment::schedules::queue_tests::revoked_reviews_rotate_without_advancing_due_slots_or_granting_authority";
  continuousSelector = "db::assessment::schedules::trigger_tests::input_changes_coalesce_without_scan_feedback_or_same_second_slot_collisions";
  deadlineSelector = "db::assessment::schedules::deadline_tests::selected_expiry_coalesces_without_refresh_feedback_and_survives_reopen";
  stabilizationSelector = "db::assessment::schedules::stabilization_tests::retained_candidate_maturation_wakes_once_without_provider_work_or_history_reset";
  stabilizationEpochSelector = "db::assessment::schedules::stabilization_tests::older_projection_reviews_catch_up_once_without_generation_feedback";
  advisorySelector = "db::assessment::advisory_snapshot::tests::retained_advisory_pages_survive_new_revisions_and_database_reopen";
  advisoryCliSelector = "db::assessment::advisory_snapshot::tests::actual_cli_retains_advisory_revisions_across_database_reopen";
  statusSelector = "db::assessment::status_snapshot_tests::status_capture_retains_real_heads_across_cancellation_and_reopen";
  statusBoundsSelector = "db::assessment::status_snapshot_tests::status_captures_bound_concurrent_storage_and_multibyte_metadata";
  statusUnassessedSelector = "db::assessment::status_snapshot_tests::pending_unassessed_heads_keep_null_evidence_and_independent_profiles";
  statusCliSelector = "db::assessment::status_snapshot_cli_tests::actual_cli_retains_status_heads_across_cancellation_and_database_reopen";
  jobAuthoritySelector = "db::assessment::authority_tests::private_job_provenance_is_immutable_scoped_and_does_not_extend_expiry";
  eventReplaySelector = "db::assessment::event_replay::tests::committed_replay_requires_contiguous_successor_custody";
  eventReopenSelector = "db::assessment::event_replay::tests::replay_position_and_expired_custody_survive_database_reopen";
  eventGapSelector = "db::assessment::event_replay::tests::an_interior_gap_is_not_filtered_event_replay";
  eventCliSelector = "db::assessment::event_replay::tests::actual_cli_watch_refuses_lost_successor_without_false_heartbeat";
in
  assert builtins.pathExists (source + "/crates/aos-hub-worker/src/oci_manifest_ingress.rs");
    pkgs.mkCargoPackage {
      pname = "aos-assessment-retained-pages-fixture";
      version = "0.1.0";
      src = source;
      cargoRoot = "crates";
      cargoWorkspaceMembers = import ./_hub-retained-workspace.nix source;
      cargoDeps = vendor;
      cargoBuildCommands = ["test --release --frozen --offline --no-run -p aos-hub-core --lib -j$NIX_BUILD_CORES"];
      cargoEnv = {
        OPENSSL_DIR = "${pkgs.openssl}";
        OPENSSL_LIB_DIR = "${pkgs.openssl}/lib";
        OPENSSL_INCLUDE_DIR = "${pkgs.openssl}/include";
        OPENSSL_NO_VENDOR = "1";
        OPENSSL_STATIC = "0";
        LIBSQLITE3_SYS_USE_PKG_CONFIG = "1";
        PROTOC = "${pkgs.protobuf}/bin/protoc";
      };
      buildDeps = [pkgs.perl pkgs.pkg-config pkgs.openssl pkgs.sqlite pkgs.protobuf pkgs.coreutils pkgs.grep];
      runtimeDeps = [pkgs.openssl pkgs.sqlite pkgs.zlib];
      installBins = false;
      doCheck = false;
      postInstall = ''
        selected="$NIX_BUILD_TOP/assessment-retained-pages-executables"
        jq -r '
          select(.reason == "compiler-artifact" and .target.name == "aos_hub_core"
            and .target.kind == ["lib"] and .profile.test == true)
          | .executable // empty
        ' "$NIX_BUILD_TOP/cargo-build-messages.jsonl" | sort -u > "$selected"
        test "$(wc -l < "$selected")" -eq 1
        IFS= read -r executable < "$selected"
        mkdir -p "$out/bin" "$out/nix-support"
        install -m 755 "$executable" "$out/bin/aos-assessment-retained-pages-fixture"
        "$out/bin/aos-assessment-retained-pages-fixture" --list --ignored --exact '${selector}' > "$out/nix-support/test-registration.txt"
        grep -Fx '${selector}: test' "$out/nix-support/test-registration.txt"
        "$out/bin/aos-assessment-retained-pages-fixture" --list --ignored --exact '${subscriptionSelector}' > "$out/nix-support/subscription-test-registration.txt"
        grep -Fx '${subscriptionSelector}: test' "$out/nix-support/subscription-test-registration.txt"
        "$out/bin/aos-assessment-retained-pages-fixture" --list --ignored --exact '${alertSelector}' > "$out/nix-support/alert-test-registration.txt"
        grep -Fx '${alertSelector}: test' "$out/nix-support/alert-test-registration.txt"
        "$out/bin/aos-assessment-retained-pages-fixture" --list --ignored --exact '${scheduleSelector}' > "$out/nix-support/schedule-test-registration.txt"
        grep -Fx '${scheduleSelector}: test' "$out/nix-support/schedule-test-registration.txt"
        "$out/bin/aos-assessment-retained-pages-fixture" --list --ignored --exact '${deliverySelector}' > "$out/nix-support/delivery-test-registration.txt"
        grep -Fx '${deliverySelector}: test' "$out/nix-support/delivery-test-registration.txt"
        "$out/bin/aos-assessment-retained-pages-fixture" --list --ignored --exact '${serviceSelector}' > "$out/nix-support/service-test-registration.txt"
        grep -Fx '${serviceSelector}: test' "$out/nix-support/service-test-registration.txt"
        "$out/bin/aos-assessment-retained-pages-fixture" --list --exact '${serviceRevocationSelector}' > "$out/nix-support/service-revocation-test-registration.txt"
        grep -Fx '${serviceRevocationSelector}: test' "$out/nix-support/service-revocation-test-registration.txt"
        "$out/bin/aos-assessment-retained-pages-fixture" --list --exact '${notificationServiceSelector}' > "$out/nix-support/notification-service-test-registration.txt"
        grep -Fx '${notificationServiceSelector}: test' "$out/nix-support/notification-service-test-registration.txt"
        "$out/bin/aos-assessment-retained-pages-fixture" --list --exact '${scheduleQueueSelector}' > "$out/nix-support/schedule-queue-test-registration.txt"
        grep -Fx '${scheduleQueueSelector}: test' "$out/nix-support/schedule-queue-test-registration.txt"
        "$out/bin/aos-assessment-retained-pages-fixture" --list --exact '${continuousSelector}' > "$out/nix-support/continuous-test-registration.txt"
        grep -Fx '${continuousSelector}: test' "$out/nix-support/continuous-test-registration.txt"
        "$out/bin/aos-assessment-retained-pages-fixture" --list --exact '${deadlineSelector}' > "$out/nix-support/deadline-test-registration.txt"
        grep -Fx '${deadlineSelector}: test' "$out/nix-support/deadline-test-registration.txt"
        "$out/bin/aos-assessment-retained-pages-fixture" --list --exact '${stabilizationSelector}' > "$out/nix-support/stabilization-test-registration.txt"
        grep -Fx '${stabilizationSelector}: test' "$out/nix-support/stabilization-test-registration.txt"
        "$out/bin/aos-assessment-retained-pages-fixture" --list --exact '${stabilizationEpochSelector}' > "$out/nix-support/stabilization-epoch-test-registration.txt"
        grep -Fx '${stabilizationEpochSelector}: test' "$out/nix-support/stabilization-epoch-test-registration.txt"
        "$out/bin/aos-assessment-retained-pages-fixture" --list --exact '${advisorySelector}' > "$out/nix-support/advisory-test-registration.txt"
        grep -Fx '${advisorySelector}: test' "$out/nix-support/advisory-test-registration.txt"
        "$out/bin/aos-assessment-retained-pages-fixture" --list --ignored --exact '${advisoryCliSelector}' > "$out/nix-support/advisory-cli-test-registration.txt"
        grep -Fx '${advisoryCliSelector}: test' "$out/nix-support/advisory-cli-test-registration.txt"
        "$out/bin/aos-assessment-retained-pages-fixture" --list --exact '${statusSelector}' > "$out/nix-support/status-test-registration.txt"
        grep -Fx '${statusSelector}: test' "$out/nix-support/status-test-registration.txt"
        "$out/bin/aos-assessment-retained-pages-fixture" --list --exact '${statusBoundsSelector}' > "$out/nix-support/statusBounds-test-registration.txt"
        grep -Fx '${statusBoundsSelector}: test' "$out/nix-support/statusBounds-test-registration.txt"
        "$out/bin/aos-assessment-retained-pages-fixture" --list --exact '${statusUnassessedSelector}' > "$out/nix-support/statusUnassessed-test-registration.txt"
        grep -Fx '${statusUnassessedSelector}: test' "$out/nix-support/statusUnassessed-test-registration.txt"
        "$out/bin/aos-assessment-retained-pages-fixture" --list --ignored --exact '${statusCliSelector}' > "$out/nix-support/statusCli-test-registration.txt"
        grep -Fx '${statusCliSelector}: test' "$out/nix-support/statusCli-test-registration.txt"
        "$out/bin/aos-assessment-retained-pages-fixture" --list --exact '${jobAuthoritySelector}' > "$out/nix-support/jobAuthority-test-registration.txt"
        grep -Fx '${jobAuthoritySelector}: test' "$out/nix-support/jobAuthority-test-registration.txt"
        "$out/bin/aos-assessment-retained-pages-fixture" --list --exact '${eventReplaySelector}' > "$out/nix-support/eventReplay-test-registration.txt"
        grep -Fx '${eventReplaySelector}: test' "$out/nix-support/eventReplay-test-registration.txt"
        "$out/bin/aos-assessment-retained-pages-fixture" --list --exact '${eventReopenSelector}' > "$out/nix-support/eventReopen-test-registration.txt"
        grep -Fx '${eventReopenSelector}: test' "$out/nix-support/eventReopen-test-registration.txt"
        "$out/bin/aos-assessment-retained-pages-fixture" --list --exact '${eventGapSelector}' > "$out/nix-support/eventGap-test-registration.txt"
        grep -Fx '${eventGapSelector}: test' "$out/nix-support/eventGap-test-registration.txt"
        "$out/bin/aos-assessment-retained-pages-fixture" --list --ignored --exact '${eventCliSelector}' > "$out/nix-support/eventCli-test-registration.txt"
        grep -Fx '${eventCliSelector}: test' "$out/nix-support/eventCli-test-registration.txt"
      '';
      passthru.testSelector = selector;
      passthru.subscriptionTestSelector = subscriptionSelector;
      passthru.alertTestSelector = alertSelector;
      passthru.scheduleTestSelector = scheduleSelector;
      passthru.deliveryTestSelector = deliverySelector;
      passthru.serviceTestSelector = serviceSelector;
      passthru.serviceRevocationTestSelector = serviceRevocationSelector;
      passthru.notificationServiceTestSelector = notificationServiceSelector;
      passthru.scheduleQueueTestSelector = scheduleQueueSelector;
      passthru.continuousTestSelector = continuousSelector;
      passthru.deadlineTestSelector = deadlineSelector;
      passthru.stabilizationTestSelector = stabilizationSelector;
      passthru.stabilizationEpochTestSelector = stabilizationEpochSelector;
      passthru.advisoryTestSelector = advisorySelector;
      passthru.advisoryCliTestSelector = advisoryCliSelector;
      passthru.statusTestSelector = statusSelector;
      passthru.statusBoundsTestSelector = statusBoundsSelector;
      passthru.statusUnassessedTestSelector = statusUnassessedSelector;
      passthru.statusCliTestSelector = statusCliSelector;
      passthru.jobAuthorityTestSelector = jobAuthoritySelector;
      passthru.eventReplayTestSelector = eventReplaySelector;
      passthru.eventReopenTestSelector = eventReopenSelector;
      passthru.eventGapTestSelector = eventGapSelector;
      passthru.eventCliTestSelector = eventCliSelector;
      meta.description = "Retained assessment list database and CLI acceptance fixture";
    }
