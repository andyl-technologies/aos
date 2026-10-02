{sourceGate}: let
  tests = [
    "reference_attribute_values_preserve_all_registered_models"
    "reference_attribute_records_preserve_fields_signatures_preimages_and_identities"
    "reference_negative_attribute_wires_require_structural_rejection"
  ];

  runTest = name: ''
    if ! cargo test --frozen --offline -p terrane-core --test attribute_vectors ${name} -- --exact \
      > "$TMPDIR/attribute-model-test.log" 2>&1; then
      cat "$TMPDIR/attribute-model-test.log"
      exit 1
    fi
    python3 -c 'import pathlib, sys; output = pathlib.Path(sys.argv[1]).read_text(); print(output); sys.exit("test result: ok. 1 passed; 0 failed; 0 ignored" not in output)' "$TMPDIR/attribute-model-test.log"
  '';
in
  sourceGate "attribute-reference-models" ''
    cd crates
    if ! test -f ../tests/terrane/attribute_vectors.py || ! test -f ../tests/terrane/attribute-models.rs; then
      printf 'Attribute reference models remain pending implementation.\n' >&2
      exit 1
    fi
    cargo build --frozen --offline -p terrane-core --example reference_blake3
    reference_binary="$CARGO_TARGET_DIR/debug/examples/reference_blake3"
    python3 ../tests/terrane/attribute_vectors.py --self-check \
      --blake3-bin "$reference_binary" > "$out/reference-result"
    python3 ../tests/terrane/attribute_vectors.py --emit \
      --blake3-bin "$reference_binary" > ../tests/terrane/attribute-reference.md
    python3 ../tests/terrane/attribute_vectors.py --check ../tests/terrane/attribute-reference.md \
      --blake3-bin "$reference_binary" >> "$out/reference-result"
    cp ../tests/terrane/attribute-reference.md "$out/reference.md"
    cp ../tests/terrane/attribute-models.rs terrane-core/tests/attribute_vectors.rs
    cargo fmt --all -- --check
    ${builtins.concatStringsSep "\n" (map runTest tests)}
    cargo clippy --frozen --offline -p terrane-core --test attribute_vectors -- -D warnings
    printf 'PASS: independent attribute models and three exact owning-codec groups\n' > "$out/result"
  ''
