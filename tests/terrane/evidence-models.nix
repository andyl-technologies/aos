{sourceGate}: let
  consumers = [
    {
      template = "selector.rs";
      source = "provenance/selector.rs";
    }
    {
      template = "context.rs";
      source = "provenance/trust/encoding.rs";
    }
    {
      template = "selected.rs";
      source = "provenance/side_attributes/serialization.rs";
    }
    {
      template = "statement.rs";
      source = "provenance/disclosure/statement.rs";
    }
  ];

  tests = [
    "provenance::selector::published_witnesses::reference_selector_models_preserve_complete_ast"
    "provenance::trust::encoding::published_witnesses::reference_context_models_preserve_versions_and_presence"
    "provenance::side_attributes::serialization::published_witnesses::reference_selected_evidence_models_preserve_all_tuple_fields"
    "provenance::disclosure::statement::published_witnesses::reference_disclosure_statement_models_preserve_all_slots_and_preimages"
    "provenance::disclosure::statement::published_witnesses::reference_disclosure_target_models_preserve_normalized_fields_and_digest"
  ];

  prepare = consumer: ''
    template="$PWD/../tests/terrane/evidence_models/${consumer.template}"
    source="terrane-core/src/${consumer.source}"
    if ! test -f "$template" || ! test -f "$source"; then
      printf 'Independent evidence field models or pure encoding prerequisites remain pending.\n' >&2
      exit 1
    fi
    printf '\n#[cfg(test)]\n#[path = "%s"]\nmod published_witnesses;\n' "$template" >> "$source"
  '';

  runTest = name: ''
    if ! cargo test --frozen --offline -p terrane-core --lib ${name} -- --exact \
      > "$TMPDIR/evidence-model-test.log" 2>&1; then
      cat "$TMPDIR/evidence-model-test.log"
      exit 1
    fi
    python3 -c 'import pathlib, sys; output = pathlib.Path(sys.argv[1]).read_text(); print(output); sys.exit("test result: ok. 1 passed; 0 failed; 0 ignored" not in output)' "$TMPDIR/evidence-model-test.log"
  '';
in
  sourceGate "evidence-reference-models" ''
    cd crates
    if ! test -f ../tests/terrane/evidence_vectors.py; then
      printf 'Independent selector and evidence reference generator remains pending.\n' >&2
      exit 1
    fi
    ${builtins.concatStringsSep "\n" (map prepare consumers)}
    cargo build --frozen --offline -p terrane-core --example reference_blake3
    reference_binary="$CARGO_TARGET_DIR/debug/examples/reference_blake3"
    python3 ../tests/terrane/evidence_vectors.py --self-check \
      --blake3-bin "$reference_binary" > "$out/reference-result"
    python3 ../tests/terrane/evidence_vectors.py --check ../docs/rfcs/0024-terrane/spec/reference/golden-vectors.md \
      --blake3-bin "$reference_binary" >> "$out/reference-result"
    cp ../docs/rfcs/0024-terrane/spec/reference/golden-vectors.md ../tests/terrane/evidence-reference.md
    cp ../tests/terrane/evidence-reference.md "$out/reference.md"
    cargo fmt --all -- --check
    ${builtins.concatStringsSep "\n" (map runTest tests)}
    cargo clippy --frozen --offline -p terrane-core --lib --tests -- -D warnings
    printf 'PASS: independent selector and evidence field models with five exact groups\n' > "$out/result"
  ''
