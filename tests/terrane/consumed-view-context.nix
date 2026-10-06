{sourceGate}: let
  tests = [
    "gc::publication::evidence::cbor::tests::view_interpretation::absent_context_preserves_published_bytes_and_reports_missing_data"
    "gc::publication::evidence::cbor::tests::view_interpretation::explicit_modes_and_recorded_old_fences_match_independent_literals"
    "gc::publication::evidence::cbor::tests::view_interpretation::optional_context_matches_independent_complete_supported_wire"
    "gc::publication::evidence::cbor::tests::view_interpretation::global_registry_and_current_whole_support_boundaries_remain_unchanged"
    "gc::publication::evidence::cbor::tests::view_interpretation::exact_view_coverage_and_original_namespace_root_are_required"
    "gc::publication::evidence::cbor::tests::view_interpretation::each_occurrence_and_override_uses_its_own_view_fence"
    "gc::publication::evidence::cbor::tests::view_interpretation::independently_selected_data_detects_each_changed_used_input"
    "gc::publication::evidence::cbor::tests::view_interpretation::signed_view_data_binds_original_root_without_certifying_signature"
    "gc::publication::evidence::cbor::tests::view_interpretation::malformed_modes_shapes_name_fences_and_headers_refuse"
    "gc::publication::evidence::cbor::tests::view_interpretation::sorted_contexts_cover_exact_views_without_changing_view_order"
    "gc::publication::evidence::cbor::tests::view_interpretation::unknown_per_view_profiles_are_data_and_refuse_interpretation"
  ];

  runTest = name: ''
    if ! cargo test --frozen --offline -p terrane-core --lib ${name} -- --exact \
      > "$TMPDIR/context-test.log" 2>&1; then
      cat "$TMPDIR/context-test.log"
      exit 1
    fi
    python3 -c 'import pathlib, sys; output = pathlib.Path(sys.argv[1]).read_text(); print(output); sys.exit("test result: ok. 1 passed; 0 failed; 0 ignored" not in output)' "$TMPDIR/context-test.log"
  '';
in
  # These ordinary-data checks do not certify completed producer context or
  # independent current selection, signed-history trust, index coverage or reuse.
  sourceGate "consumed-view-context" ''
    cd crates
    ${builtins.concatStringsSep "\n" (map runTest tests)}
    cargo clippy --frozen --offline -p terrane-core --lib --tests -- -D warnings
    printf 'PASS: eleven exact consumed-view context data codec groups\n' > "$out/result"
  ''
