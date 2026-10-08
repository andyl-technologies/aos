{sourceGate}: let
  selectors = [
    "ref_advance::active_completion_tests::native_active_completion_dropped_required_owner_binding_refuses_publication"
    "ref_advance::active_completion_tests::native_active_completion_verifies_indexed_owner_before_selected_ack"
    "ref_advance::active_completion_tests::native_active_completion_checks_every_shared_graft_occurrence"
    "ref_advance::active_completion_tests::native_active_completion_missing_primary_never_selects_ref_or_lineage"
    "ref_advance::active_completion_tests::native_active_completion_legacy_one_never_coerces_indexed_view"
    "ref_advance::active_completion_tests::native_active_completion_conflicting_same_view_selection_refuses"
    "ref_advance::active_completion_tests::native_active_completion_checks_each_signed_requirement_field"
    "ref_advance::active_completion_tests::native_active_completion_late_original_failure_promotes_no_views"
    "ref_advance::active_completion_tests::native_active_metadata_admits_index_roles_but_not_namespace_use"
    "ref_advance::active_completion_tests::native_active_completion_divergent_primary_never_promotes"
  ];
in
  sourceGate "native-active-view-completion" ''
    cd crates
    mkdir -p "$out/logs"
    cargo test --frozen --offline -p terrane --no-default-features \
      --features tokio,surface-sdk --lib -- --list > "$out/native-tests.txt"
    python3 ../tests/terrane/check_native_gate.py inventory \
      "$out/native-tests.txt" '${builtins.toJSON selectors}'

    case_index=0
    for test_name in ${builtins.concatStringsSep " " selectors}; do
      case_index=$((case_index + 1))
      report="$out/logs/case-$case_index.log"
      if ! cargo test --frozen --offline -p terrane --no-default-features \
        --features tokio,surface-sdk --lib "$test_name" -- --exact \
        > "$report" 2>&1; then
        cat "$report"
        exit 1
      fi
      python3 ../tests/terrane/check_native_gate.py execution \
        "$report" "[\"$test_name\"]"
    done
    printf 'PASS: active signed-view completion (10 exact cases)\n' > "$out/result"
  ''
