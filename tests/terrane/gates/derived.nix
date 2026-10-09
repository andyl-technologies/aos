{sourceGate, ...}: {
  derived-attr-record = sourceGate "derived-attr-record" ''
    cd crates
    cargo test --frozen --offline -p terrane-core --lib derived:: > "$TMPDIR/core.log"
    cargo test --frozen --offline -p terrane --lib --features tokio derived:: > "$TMPDIR/native.log"
    python3 - "$TMPDIR/core.log" "$TMPDIR/native.log" <<'PY'
    import pathlib, re, sys
    required = [
        ["derived::tests::record_canonical_fixture_and_separate_producer_identity",
         "derived::tests::hashes_known_vectors_include_git_header_and_stream_order",
         "derived::tests::unknown_function_versions_are_retained_but_never_verified",
         "derived::tests::optional_signature_codec_preserves_legacy_bytes_and_rejects_wrong_lengths",
         "derived::tests::dictionary_record_carries_chunk_digest_and_remains_supplied_metadata",
         "derived::provenance_tests::detached_signature_binds_all_fields_and_requires_producer_object_witness",
         "derived::provenance_tests::producer_requires_signed_object_value_and_separate_attribute_origin",
         "derived::provenance_tests::disclosure_tests::signed_disclosure_producer_requires_completed_batch_before_typed_evidence",
         "derived::provenance_tests::disclosure_tests::invalid_disclosure_certificate_cannot_gain_authority_from_valid_record_signature",
         "derived::provenance_tests::disclosure_tests::signed_non_disclosure_producer_requires_actual_root_scope_completion",
         "derived::provenance_tests::disclosure_tests::legacy_inline_carrying_view_does_not_bypass_actual_producer_context"],
        ["derived::tests::effective_requirements_produce_records_accepted_by_changed_entry_validation",
         "derived::tests::store_object_reassembles_verified_chunks_in_manifest_order",
         "derived::tests::store_object_rejects_invalid_manifest_length_sum_before_chunk_get",
         "derived::tests::store_object_rejects_missing_plaintext_blake3_before_chunk_get",
         "derived::tests::signed_tests::signed_required_side_records_gain_checked_producer_evidence_and_reuse_metadata",
         "derived::tests::signed_tests::dictionary_selection_requires_checked_class_and_explicit_unique_mapping",
         "derived::tests::dictionary_tests::named_dictionary_fetch_verifies_plaintext_before_object_hashing",
         "derived::tests::immutable_signature_variants_coexist_and_exact_quarantine_preserves_other_variant",
         "derived::storage_tests::durable_catalog_reopen_and_quarantine_preserve_other_attributes",
         "derived::storage_tests::unavailable_producer_evidence_never_publishes_durable_quarantine",
         "derived::tests::signed_tests::context_tests::pending_actual_root_context_propagates_without_durable_quarantine"],
    ]
    for name, tests in zip(sys.argv[1:], required):
        output = pathlib.Path(name).read_text()
        print(output)
        if not re.search(r"test result: ok\. [1-9][0-9]* passed; 0 failed", output):
            raise SystemExit("derived attribute suite did not execute passing tests")
        for test in tests:
            if f"test {test} ... ok" not in output:
                raise SystemExit(f"required derived attribute test did not pass: {test}")
    PY
    printf 'PASS: canonical records, streaming hashes, bounded classifiers, durable authoritative side table and signed producer evidence\n' > "$out/result"
  '';
}
