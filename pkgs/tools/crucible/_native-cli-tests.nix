# Assigns exact CLI test identities to their disposable kernel gates.
# The Apache controller sandbox has no installed source/catalog/registry quotas;
# these tests remain required in the corresponding gates rather than gaining
# an unconfigured component fallback or an ignore attribute.
{lib}: let
  pairedProcessTests = selectors:
    lib.concatMap (target:
      map (selector: {
        inherit target;
        selector =
          if target == "gate_campaign_store_composition"
          then "campaign_store_process::${selector}"
          else selector;
      })
      selectors) ["campaign_store_process" "gate_campaign_store_composition"];

  byGate = {
    finding = pairedProcessTests [
      "finding_exact_vm::packaged_finding_bundle_fork_write_is_noncanonical"
      "finding_exact_vm::packaged_finding_bundle_replays_without_source_owner"
      "finding_exact_vm::packaged_finding_bundle_retains_selected_fault_and_guest_response"
      "public_campaign_debug_opens_authenticated_finding_at_fast_midpoint"
    ];
    gc =
      map (selector: {
        target = "crucible-unit";
        inherit selector;
      }) [
        "cli_store::tests::offline_gc_plans_reopens_and_applies_one_exact_empty_store"
        "cli_store::tests::offline_gc_cancellation_is_durable_and_apply_refuses_it"
      ]
      ++ pairedProcessTests [
        "public_campaign_store_flight_survives_gc_and_service_restart"
        "public_checkpoint_pause_survives_stopped_service_gc_and_cold_resume"
        "public_composed_store_flight_evicts_cache_and_flushes_write_back"
        "archive_transfer::public_offline_archive_transfer_reports_and_authenticates_sensitive_closure"
        "archive_transfer::public_archive_transfer_is_backend_neutral_across_compressed_stores"
        "archive_transfer::public_worked_network_archive_survives_packed_repack_outage_and_corruption"
      ];
    offline =
      map (selector: {
        target = "machine_readable";
        inherit selector;
      }) [
        "cli_exit_machine_readable_process_stdout_is_pure_json"
        "cli_selftest_honors_machine_output_trace_and_quiet"
        "cli_save_machine_readable_jsonl_rejects_session_owned_export"
        "cli_exit_machine_readable_search_fuzz_jsonl_reports_final_outcome"
        "cli_exit_machine_readable_search_retained_evidence_failure_jsonl_reports_final_outcome"
        "cli_exit_machine_readable_replay_check_jsonl_reports_final_outcome"
        "cli_exit_machine_readable_replay_error_reports_one_failed_outcome"
        "cli_exit_machine_readable_replay_to_savepoint_jsonl_reports_final_outcome"
      ]
      ++ [
        {
          target = "serve_process";
          selector = "serve_process_exits_zero_on_sigterm";
        }
      ]
      ++ pairedProcessTests ["packaged_campaign_service_uses_mtls_without_debug_authority"];
    planning =
      map (selector: {
        target = "native_input_planning";
        inherit selector;
      }) [
        "plain_native_run_plans_and_completes_on_one_deployed_owner"
        "plain_native_fuzz_plans_and_records_real_coverage_on_one_deployed_owner"
      ];
  };
  gatePaths = {
    finding = "checks.crucible.phase5.cliNativeFindingIntegration";
    gc = "checks.crucible.phase5.cliNativeGcIntegration";
    offline = "checks.crucible.phase5.cliNativeOfflineIntegration";
    planning = "checks.crucible.phase5.cliNativePlanningIntegration";
  };
  assignments = lib.concatLists (lib.mapAttrsToList (name: executions:
    map (execution:
      execution
      // {
        gate = gatePaths.${name};
        binary =
          if execution.target == "crucible-unit"
          then "crucible"
          else execution.target;
      })
    executions)
  byGate);
  assignedTests =
    lib.concatMapStringsSep " or " (execution: "(binary(=${execution.binary}) and test(=${execution.selector}))")
    assignments;
in {
  inherit byGate assignments;
  # Match both the CLI binary and full test identity so ordinary tests in the
  # same binaries, and all tests in other packages, remain in the sandbox run.
  nextestFilter = "not (package(=crucible-cli) and (${assignedTests}))";
  # Cargo/libtest uses substring skips; full names preserve the gate inventory
  # when a workspace validation command consumes this same assignment table.
  cargoSkipFlags = lib.concatMapStringsSep " " (execution: "--skip ${execution.selector}") assignments;
}
