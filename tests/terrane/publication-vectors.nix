{sourceGate}: let
  tests = [
    "gc::publication::cbor::tests::published::published_bindings_and_activation_match_described_models"
    "gc::publication::cbor::tests::published::published_empty_history_preserves_never_and_unknown_distinction"
    "gc::publication::evidence::cbor::tests::published::published_original_and_trust_vectors_match_described_models"
    "gc::publication::evidence::cbor::tests::published::published_guard_and_policy_vectors_match_described_models"
    "gc::publication::evidence::cbor::tests::published::published_import_binding_and_trust_match_exact_raw_digests"
    "gc::publication::evidence::cbor::tests::published::published_consumed_inputs_and_legacy_lineage_fix_claim_bytes_only"
    "gc::publication::cbor::tests::published::published_state_and_pointers_match_described_models"
    "gc::publication::cbor::tests::published::published_proof_variants_fix_structural_claims_only"
    "gc::publication::cbor::tests::published::published_delta_and_next_transaction_match_described_models"
    "gc::publication::cbor::tests::published::published_missing_genesis_inventory_rejects_independent_wire_inputs"
  ];

  # This owning suite proves the additive D-84 corpus. Complete conformance
  # additionally requires every other suite in the golden-vectors gate.
  runTest = name: ''
    cargo test --frozen --offline -p terrane-core --lib ${name} -- --exact > "$TMPDIR/vector-test.log"
    python3 - "$TMPDIR/vector-test.log" <<'PYTEST'
    import pathlib
    import sys

    output = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
    print(output)
    if "test result: ok. 1 passed; 0 failed; 0 ignored" not in output:
        raise SystemExit("required published-vector test did not execute successfully")
    PYTEST
  '';
in
  sourceGate "publication-format-vectors" ''
    cd crates
    cargo build --frozen --offline -p terrane-core --example reference_blake3
    python3 ../tests/terrane/publication_vectors.py --check \
      ../docs/rfcs/0024-terrane/spec/reference/golden-vectors.md \
      --blake3-bin "$CARGO_TARGET_DIR/debug/examples/reference_blake3" > "$out/reference-result"
    ${builtins.concatStringsSep "\n" (map runTest tests)}
    printf 'PASS: 39 independent published D-79 format vectors and ten exact model tests\n' \
      > "$out/result"
  ''
