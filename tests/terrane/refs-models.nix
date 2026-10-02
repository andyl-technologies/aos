{sourceGate}: let
  tests = [
    "reference_modern_commit_models_preserve_optional_fields_and_preimage"
    "reference_ref_record_models_preserve_policy_envelope_fields_and_preimage"
    "reference_reflog_models_preserve_reason_expected_and_predecessor_fields"
    "reference_negative_ref_wires_require_structural_rejection"
  ];

  runTest = name: ''
    if ! cargo test --frozen --offline -p terrane-core --test refs_vectors ${name} -- --exact \
      > "$TMPDIR/refs-model-test.log" 2>&1; then
      cat "$TMPDIR/refs-model-test.log"
      exit 1
    fi
    python3 -c 'import pathlib, sys; output = pathlib.Path(sys.argv[1]).read_text(); print(output); sys.exit("test result: ok. 1 passed; 0 failed; 0 ignored" not in output)' "$TMPDIR/refs-model-test.log"
  '';
in
  sourceGate "refs-reference-models" ''
    cd crates
    if ! test -f ../tests/terrane/refs_vectors.py || ! test -f ../tests/terrane/refs-models.rs || ! test -d ../tests/terrane/refs_models; then
      printf 'Independent modern commit and ref record field models remain pending implementation.\n' >&2
      exit 1
    fi
    cargo build --frozen --offline -p terrane-core --example reference_blake3
    reference_binary="$CARGO_TARGET_DIR/debug/examples/reference_blake3"
    python3 ../tests/terrane/refs_vectors.py --self-check \
      --blake3-bin "$reference_binary" > "$out/reference-result"
    python3 ../tests/terrane/refs_vectors.py --check ../docs/rfcs/0024-terrane/spec/reference/golden-vectors.md \
      --blake3-bin "$reference_binary" >> "$out/reference-result"
    cp ../docs/rfcs/0024-terrane/spec/reference/golden-vectors.md ../tests/terrane/refs-reference.md
    cp ../tests/terrane/refs-reference.md "$out/reference.md"
    cp ../tests/terrane/refs-models.rs terrane-core/tests/refs_vectors.rs
    cp -r ../tests/terrane/refs_models terrane-core/tests/refs_models
    cargo fmt --all -- --check
    ${builtins.concatStringsSep "\n" (map runTest tests)}
    cargo clippy --frozen --offline -p terrane-core --test refs_vectors -- -D warnings
    printf 'PASS: independent modern commit/ref models and four exact owning-codec groups\n' > "$out/result"
  ''
