{sourceGate}: let
  tests = [
    "reference_index_owner_bindings_and_recipes_preserve_exact_formats"
    "reference_index_opaque_keys_preserve_complete_canonical_values"
    "reference_index_historical_nodes_preserve_data_without_activation"
    "reference_index_carrier_nodes_preserve_complete_models_and_descriptors"
    "reference_index_source_models_match_complete_independent_occurrences"
    "reference_index_contextual_relationships_refuse_invalid_routes_and_gaps"
    "reference_index_format_negatives_refuse_independently_supplied_wires"
  ];

  runTest = name: ''
    if ! cargo test --frozen --offline -p terrane-core --test index_vectors ${name} -- --exact \
      > "$TMPDIR/index-model-test.log" 2>&1; then
      cat "$TMPDIR/index-model-test.log"
      exit 1
    fi
    python3 -c 'import pathlib, sys; output = pathlib.Path(sys.argv[1]).read_text(); print(output); sys.exit("test result: ok. 1 passed; 0 failed; 0 ignored" not in output)' "$TMPDIR/index-model-test.log"
  '';
in
  sourceGate "index-reference-models" ''
    cd crates
    if ! test -f ../tests/terrane/index_vectors.py || ! test -f ../tests/terrane/index-models.rs || ! test -d ../tests/terrane/index_models; then
      printf 'Independent index format and hierarchical occurrence witnesses remain pending.\n' >&2
      exit 1
    fi
    cargo build --frozen --offline -p terrane-core --example reference_blake3
    reference_binary="$CARGO_TARGET_DIR/debug/examples/reference_blake3"
    python3 ../tests/terrane/index_vectors.py --self-check \
      --blake3-bin "$reference_binary" > "$out/reference-result"
    python3 ../tests/terrane/index_vectors.py --check ../docs/rfcs/0024-terrane/spec/reference/golden-vectors.md \
      --blake3-bin "$reference_binary" >> "$out/reference-result"
    cp ../docs/rfcs/0024-terrane/spec/reference/golden-vectors.md ../tests/terrane/index-reference.md
    cp ../tests/terrane/index-reference.md "$out/reference.md"
    cp ../tests/terrane/index-models.rs terrane-core/tests/index_vectors.rs
    cp -r ../tests/terrane/index_models terrane-core/tests/index_models
    cargo fmt --all -- --check
    ${builtins.concatStringsSep "\n" (map runTest tests)}
    cargo clippy --frozen --offline -p terrane-core --test index_vectors -- -D warnings
    printf 'PASS: independent index format/carrier witnesses and seven exact owning-codec groups\n' > "$out/result"
  ''
