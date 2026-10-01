{sourceGate, ...}: let
  runTest = name: ''
    cargo test --frozen --offline -p terrane-core --lib provenance::tests::${name} -- --exact > "$TMPDIR/test.log"
    python3 -c 'import pathlib, sys; output = pathlib.Path(sys.argv[1]).read_text(); print(output); sys.exit("test result: ok. 1 passed; 0 failed" not in output)' "$TMPDIR/test.log"
  '';
in {
  prov-commit-signature = sourceGate "prov-commit-signature" ''
    cd crates
    cargo build --frozen --offline --no-default-features -p terrane-core --lib
    ${runTest "prov_commit_signature_binds_exact_preimage_and_signed_identity"}
    ${runTest "prov_commit_verify_rejects_tampering_missing_token_and_wrong_context"}
    ${runTest "prov_commit_signature_uses_last_attenuation_key"}
    ${runTest "context::prov_commit_signature_binds_context_even_when_changed_scope_is_authorized"}
    ${runTest "context::prov_commit_history_preserves_original_scope_with_narrow_root_grants"}
    ${runTest "context::prov_commit_context_rejects_tampered_scope_and_unvalidated_roots"}
    ${runTest "context::prov_commit_authored_requires_context_and_legacy_bytes_remain_explicit"}
    ${runTest "context::prov_commit_context_canonicalizes_unsigned_root_pairs_and_rejects_duplicates"}
    ${runTest "snapshot::prov_snapshot_signature_binds_exact_preimage_and_terminal_key"}
    ${runTest "snapshot::prov_snapshot_verification_rejects_wrong_target_scope_and_signature"}
    ${runTest "snapshot::prov_snapshot_tag_scope_accepts_admin_implication_and_rejects_commit_only"}
    ${runTest "snapshot::prov_snapshot_tag_scope_enforces_exact_source_caveats"}
    printf 'PASS: pure terminal-key commit signatures and embedded authorization\n' > "$out/result"
  '';

  prov-selector-presets = sourceGate "prov-selector-presets" ''
    cd crates
    ${runTest "prov_selector_presets_parse_closed_ast_and_deep_input"}
    ${runTest "prov_selector_presets_distinguish_fold_acceptance_from_introduction"}
    ${runTest "prov_entry_preserve_metadata_and_sources_without_parent_ancestry"}
    ${runTest "prov_selector_presets_missing_evidence_stays_absent_under_negation"}
    ${runTest "prov_entry_preserve_rejects_unverified_tree_and_invalid_ancestors"}
    ${runTest "prov_fold_reintroduction_records_verified_original_introduction"}
    ${runTest "prov_selector_presets_root_policy_cannot_be_widened_by_view"}
    ${runTest "prov_attribute_producer_is_independent_of_content_introduction"}
    ${runTest "prov_selector_presets_graft_policy_applies_without_subroot_bypass"}
    ${runTest "prov_fold_acceptance_survives_receipt_path_changes"}
    ${runTest "prov_selector_presets_descendant_baseline_cannot_widen_ancestor_trust"}
    ${runTest "prov_selector_presets_signed_key_names_terminal_public_key_bytes"}
    ${runTest "prov_entry_preserve_index_receipts_use_checked_opaque_keys"}
    ${runTest "prov_selector_presets_candidate_decisions_bind_full_signed_entry"}
    ${runTest "prov_attribute_acceptance_does_not_borrow_content_acceptance"}
    ${runTest "prov_property_wrappers_resolve_inheritance_and_graft_overrides"}
    ${runTest "prov_external_sources_preserve_producers_without_granting_acceptance"}
    ${runTest "prov_attribute_producer_rejects_equal_value_inherited_on_changed_content"}
    printf 'PASS: closed trust presets and verified entry preservation\n' > "$out/result"
  '';
}
