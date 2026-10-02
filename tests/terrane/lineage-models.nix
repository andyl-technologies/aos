{sourceGate}: let
  tests = [
    "reference_control_pin_models_preserve_all_kinds_and_owners"
    "reference_consumed_root_models_preserve_layers_and_occurrences"
    "reference_consumed_view_models_preserve_domains_and_order"
    "reference_lineage_used_inputs_preserve_complete_nested_fields"
    "reference_checked_lineage_preserves_complete_source_fields"
    "reference_lineage_field_negatives_require_structural_rejection"
  ];

  runTest = name: ''
    if ! cargo test --frozen --offline -p terrane-core --test lineage_vectors ${name} -- --exact \
      > "$TMPDIR/lineage-model-test.log" 2>&1; then
      cat "$TMPDIR/lineage-model-test.log"
      exit 1
    fi
    python3 -c 'import pathlib, sys; output = pathlib.Path(sys.argv[1]).read_text(); print(output); sys.exit("test result: ok. 1 passed; 0 failed; 0 ignored" not in output)' "$TMPDIR/lineage-model-test.log"
  '';
in
  sourceGate "lineage-reference-models" ''
    cd crates
    if ! test -f ../tests/terrane/lineage_vectors.py || ! test -f ../tests/terrane/lineage-models.rs || ! test -d ../tests/terrane/lineage_models; then
      printf 'Independent consumed-lineage record field models remain pending.\n' >&2
      exit 1
    fi
    cargo build --frozen --offline -p terrane-core --example reference_blake3
    reference_binary="$CARGO_TARGET_DIR/debug/examples/reference_blake3"
    python3 ../tests/terrane/lineage_vectors.py --self-check \
      --blake3-bin "$reference_binary" > "$out/reference-result"
    python3 ../tests/terrane/lineage_vectors.py --check ../docs/rfcs/0024-terrane/spec/reference/golden-vectors.md \
      --blake3-bin "$reference_binary" >> "$out/reference-result"
    cp ../docs/rfcs/0024-terrane/spec/reference/golden-vectors.md ../tests/terrane/lineage-reference.md
    cp ../tests/terrane/lineage-reference.md "$out/reference.md"
    cp ../tests/terrane/lineage-models.rs terrane-core/tests/lineage_vectors.rs
    cp -r ../tests/terrane/lineage_models terrane-core/tests/lineage_models
    cargo fmt --all -- --check
    ${builtins.concatStringsSep "\n" (map runTest tests)}
    cargo clippy --frozen --offline -p terrane-core --test lineage_vectors -- -D warnings
    printf 'PASS: ordinary consumed-lineage fields and six exact pure codec groups\n' > "$out/result"
  ''
