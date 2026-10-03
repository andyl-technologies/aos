{sourceGate, ...}: let
  runTests = filter: ''
    cargo test --frozen --offline -p terrane-core --lib ${filter} > "$TMPDIR/test.log"
    python3 -c 'import pathlib, re, sys; output = pathlib.Path(sys.argv[1]).read_text(); print(output); sys.exit(not re.search(r"test result: ok\. [1-9][0-9]* passed; 0 failed", output))' "$TMPDIR/test.log"
  '';
in {
  property-resolution = sourceGate "property-resolution" ''
    cd crates
    ${runTests "properties::tests::resolution"}
    ${runTests "properties::depth_tests"}
    ${runTests "gc::publication::evidence::cbor::tests::guard::property_revisions_preserve_legacy_and_bind_index_roots_exactly -- --exact"}
    ${runTests "gc::publication::evidence::cbor::tests::guard::property_revision_vocabulary_mismatches_refuse -- --exact"}
    ${runTests "gc::publication::evidence::validation::policy::tests::later_property_names_remain_inert_under_their_recorded_revision -- --exact"}
    ${runTests "gc::publication::evidence::cbor::tests::lineage::enclosing_lineage_preserves_recorded_inert_property_names -- --exact"}
    ${runTests "indexing::tests::owner_bindings_require_canonical_noninherited_root_values -- --exact"}
    ${runTests "indexing::carrier_tests::gap_bindings_require_primary_root_placement_and_exact_wrapper -- --exact"}
    ${runTests "indexing::carrier_tests::structural_index_names_do_not_become_value_inputs -- --exact"}
    ${runTests "gc::publication::evidence::validation::policy::tests::property_and_attribute_revisions_bind_structural_index_names_exactly -- --exact"}
    ${runTests "gc::publication::evidence::validation::policy::tests::legacy_semantic_contexts_preserve_inert_index_carriers -- --exact"}
    ${runTests "properties::semantics::tests::resolution_recorded_revisions_preserve_inert_later_names -- --exact"}
    ${runTests "properties::semantics::tests::resolution_revisions_bind_defaults_and_graft_placement_exactly -- --exact"}
    ${runTests "properties::semantics::tests::resolution_unknown_revisions_and_unregistered_extensions_refuse -- --exact"}
    ${runTests "provenance::root_context::snapshot::tests::snapshot_recorded_revisions_preserve_defaults_and_inert_names -- --exact"}
    ${runTests "provenance::root_context::snapshot::tests::snapshot_recorded_revisions_follow_full_and_parent_graft_paths -- --exact"}
    ${runTests "provenance::root_context::snapshot::tests::snapshot_recorded_revisions_reject_untrusted_names_and_placement -- --exact"}
    ${runTests "provenance::root_context::snapshot::tests::authoring_plans_use_explicit_recorded_property_context -- --exact"}
    printf 'PASS: closed registry and view-path property resolution\n' > "$out/result"
  '';

  property-required-attrs = sourceGate "property-required-attrs" ''
    cd crates
    ${runTests "properties::tests::required_attrs"}
    printf 'PASS: changed-entry attribute requirements and completeness\n' > "$out/result"
  '';

  property-domain-reference = sourceGate "property-domain-reference" ''
    cd crates
    ${runTests "properties::tests::domain_reference"}
    printf 'PASS: disclosure references and boundary transitions\n' > "$out/result"
  '';
}
