{sourceGate}: let
  selectors = [
    "indexing::tests::index_loader_loads_bound_hierarchical_graph_without_mutation"
    "indexing::tests::index_loader_preserves_physical_and_contextual_node_checks"
    "indexing::tests::index_loader_reports_missing_bindings_and_unavailable_evidence"
    "indexing::tests::index_loader_refuses_divergent_relationships_and_keeps_work_separate"
    "indexing::tests::load_source_reads_unbound_namespace_without_auxiliary_reads"
    "indexing::tests::load_source_preserves_shared_grafts_and_internal_physical_contexts"
    "indexing::tests::load_source_keeps_typed_source_failures_and_selected_revisions"
  ];
in
  # Immutable loading and relationship verification precede current view checks.
  sourceGate "native-index-loading" ''
    cd crates
    cargo test --frozen --offline -p terrane --no-default-features \
      --features tokio,surface-sdk --lib -- --list > "$out/discovery.log"
    python3 ../tests/terrane/check_native_gate.py inventory \
      "$out/discovery.log" '${builtins.toJSON selectors}'

    case_number=0
    for test_name in ${builtins.concatStringsSep " " selectors}; do
      case_number=$((case_number + 1))
      case_log="$out/case-$case_number.log"
      if ! cargo test --frozen --offline -p terrane --no-default-features \
        --features tokio,surface-sdk --lib "$test_name" -- --exact \
        > "$case_log" 2>&1; then
        cat "$case_log"
        exit 1
      fi
      python3 ../tests/terrane/check_native_gate.py execution \
        "$case_log" "[\"$test_name\"]"
    done
    printf 'PASS: seven exact immutable index loading and refusal cases\n' > "$out/result"
  ''
