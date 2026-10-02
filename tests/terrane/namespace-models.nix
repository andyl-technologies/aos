{sourceGate}: let
  tests = [
    "reference_entry_models_preserve_optional_metadata_and_kind_fields"
    "reference_root_property_models_preserve_nested_values_and_identity"
    "reference_negative_namespace_wires_require_structural_rejection"
  ];

  runTest = name: ''
    if ! cargo test --frozen --offline -p terrane-core --test namespace_vectors ${name} -- --exact \
      > "$TMPDIR/namespace-model-test.log" 2>&1; then
      cat "$TMPDIR/namespace-model-test.log"
      exit 1
    fi
    python3 -c 'import pathlib, sys; output = pathlib.Path(sys.argv[1]).read_text(); print(output); sys.exit("test result: ok. 1 passed; 0 failed; 0 ignored" not in output)' "$TMPDIR/namespace-model-test.log"
  '';
in
  sourceGate "namespace-reference-models" ''
    cd crates
    if ! test -f ../tests/terrane/namespace_vectors.py || ! test -f ../tests/terrane/namespace-models.rs; then
      printf 'Namespace reference models remain pending implementation.\n' >&2
      exit 1
    fi
    cargo build --frozen --offline -p terrane-core --example reference_blake3
    reference_binary="$CARGO_TARGET_DIR/debug/examples/reference_blake3"
    python3 ../tests/terrane/namespace_vectors.py --self-check \
      --blake3-bin "$reference_binary" > "$out/reference-result"
    python3 ../tests/terrane/namespace_vectors.py --check \
      ../docs/rfcs/0024-terrane/spec/reference/golden-vectors.md \
      --blake3-bin "$reference_binary" >> "$out/reference-result"
    cp ../docs/rfcs/0024-terrane/spec/reference/golden-vectors.md ../tests/terrane/namespace-reference.md
    cp ../tests/terrane/namespace-reference.md "$out/reference.md"
    cp ../tests/terrane/namespace-models.rs terrane-core/tests/namespace_vectors.rs
    cargo fmt --all -- --check
    ${builtins.concatStringsSep "\n" (map runTest tests)}
    cargo clippy --frozen --offline -p terrane-core --test namespace_vectors -- -D warnings
    printf 'PASS: independent namespace models and three exact owning-codec groups\n' > "$out/result"
  ''
