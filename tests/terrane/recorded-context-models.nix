{sourceGate}: let
  consumers = [
    {
      template = "encoding.rs";
      source = "provenance/trust/encoding.rs";
    }
    {
      template = "context.rs";
      source = "provenance/trust/context.rs";
    }
    {
      template = "recipe.rs";
      source = "algebra/trust.rs";
    }
  ];

  tests = [
    "provenance::trust::encoding::recorded_published_witnesses::reference_recorded_context_encoder_preserves_complete_fields"
    "provenance::trust::context::recorded_published_witnesses::reference_recorded_context_decoder_refuses_independent_malformed_wires"
    "algebra::trust::recorded_published_witnesses::reference_recorded_context_recipes_bind_complete_configuration_and_keys"
  ];

  prepare = consumer: ''
    template="$PWD/../tests/terrane/recorded_context_models/${consumer.template}"
    source="terrane-core/src/${consumer.source}"
    if ! test -f "$template" || ! test -f "$source"; then
      printf 'Independent recorded-context field models or pure codec prerequisites remain pending.\n' >&2
      exit 1
    fi
    printf '\n#[cfg(test)]\n#[path = "%s"]\nmod recorded_published_witnesses;\n' "$template" >> "$source"
  '';

  runTest = name: ''
    if ! cargo test --frozen --offline -p terrane-core --lib ${name} -- --exact \
      > "$TMPDIR/recorded-context-model-test.log" 2>&1; then
      cat "$TMPDIR/recorded-context-model-test.log"
      exit 1
    fi
    python3 -c 'import pathlib, sys; output = pathlib.Path(sys.argv[1]).read_text(); print(output); sys.exit("test result: ok. 1 passed; 0 failed; 0 ignored" not in output)' "$TMPDIR/recorded-context-model-test.log"
  '';
in
  sourceGate "recorded-context-reference-models" ''
    cd crates
    if ! test -f ../tests/terrane/recorded_context_vectors.py; then
      printf 'Independent recorded-context reference generator remains pending.\n' >&2
      exit 1
    fi
    ${builtins.concatStringsSep "\n" (map prepare consumers)}
    cargo build --frozen --offline -p terrane-core --example reference_blake3
    reference_binary="$CARGO_TARGET_DIR/debug/examples/reference_blake3"
    python3 ../tests/terrane/recorded_context_vectors.py --self-check \
      --blake3-bin "$reference_binary" > "$out/reference-result"
    python3 ../tests/terrane/recorded_context_vectors.py --check ../docs/rfcs/0024-terrane/spec/reference/golden-vectors.md \
      --blake3-bin "$reference_binary" >> "$out/reference-result"
    cp ../docs/rfcs/0024-terrane/spec/reference/golden-vectors.md ../tests/terrane/recorded-context-reference.md
    cp ../tests/terrane/recorded-context-reference.md "$out/reference.md"
    cargo fmt --all -- --check
    ${builtins.concatStringsSep "\n" (map runTest tests)}
    cargo clippy --frozen --offline -p terrane-core --lib --tests -- -D warnings
    printf 'PASS: ordinary recorded-context fields and three exact owning-codec groups\n' > "$out/result"
  ''
