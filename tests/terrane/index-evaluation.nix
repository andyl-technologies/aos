{sourceGate}: let
  tests = [
    "hierarchical_index_matches_independent_source_occurrences"
    "verification_rejects_divergent_rows_routes_and_gaps"
    "role_contexts_preserve_shared_nodes_without_false_authority"
  ];

  discoveryTests = [
    "source_discovery_preserves_local_hops_and_expands_changed_grafts"
    "source_discovery_skips_equal_frontiers_and_reports_logical_changes"
    "source_discovery_refuses_invalid_graphs_and_contexts"
  ];

  maintenanceTests = [
    "maintenance_matches_complete_independent_routes_and_logical_deltas"
    "maintenance_repeated_updates_retain_stable_storage_and_bounded_maps"
    "maintenance_batches_all_levels_and_conserves_real_boundary_work"
    "maintenance_refuses_invalid_relations_and_mismatched_update_bindings"
    "maintenance_separates_initial_rebuild_validation_and_export_work"
  ];

  runTest = name: ''
    if ! cargo test --frozen --offline -p terrane-core --lib indexing::evaluation_tests::${name} -- --exact \
      > "$TMPDIR/index-evaluation-test.log" 2>&1; then
      cat "$TMPDIR/index-evaluation-test.log"
      exit 1
    fi
    python3 -c 'import pathlib, sys; output = pathlib.Path(sys.argv[1]).read_text(); print(output); sys.exit("test result: ok. 1 passed; 0 failed; 0 ignored" not in output)' "$TMPDIR/index-evaluation-test.log"
  '';

  runDiscoveryTest = name: ''
    if ! cargo test --frozen --offline -p terrane-core --lib indexing::incremental::tests::${name} -- --exact \
      > "$TMPDIR/index-discovery-test.log" 2>&1; then
      cat "$TMPDIR/index-discovery-test.log"
      exit 1
    fi
    python3 -c 'import pathlib, sys; output = pathlib.Path(sys.argv[1]).read_text(); print(output); sys.exit("test result: ok. 1 passed; 0 failed; 0 ignored" not in output)' "$TMPDIR/index-discovery-test.log"
  '';

  runMaintenanceTest = name: ''
    if ! cargo test --frozen --offline -p terrane-core --lib indexing::maintenance::tests::${name} -- --exact \
      > "$TMPDIR/index-maintenance-test.log" 2>&1; then
      cat "$TMPDIR/index-maintenance-test.log"
      exit 1
    fi
    python3 -c 'import pathlib, sys; output = pathlib.Path(sys.argv[1]).read_text(); print(output); sys.exit("test result: ok. 1 passed; 0 failed; 0 ignored" not in output)' "$TMPDIR/index-maintenance-test.log"
  '';
in
  sourceGate "index-evaluation" ''
    cd crates
    ${builtins.concatStringsSep "\n" (map runTest tests)}
    ${builtins.concatStringsSep "\n" (map runDiscoveryTest discoveryTests)}
    ${builtins.concatStringsSep "\n" (map runMaintenanceTest maintenanceTests)}
    cargo clippy --frozen --offline -p terrane-core --all-targets -- -D warnings
    printf 'PASS: pure canonical index relationships, changed-source discovery and repeatable maintenance\n' > "$out/result"
  ''
