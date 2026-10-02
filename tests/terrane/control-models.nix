{sourceGate}: let
  tests = [
    "reference_backend_binding_models_preserve_all_alternatives"
    "reference_original_control_models_preserve_all_registered_versions"
    "reference_guard_snapshot_models_preserve_complete_nested_fields"
    "reference_portable_snapshot_and_genesis_models_preserve_mandatory_inventory"
    "reference_publication_proof_models_preserve_all_alternatives"
    "reference_publication_control_negatives_require_structural_rejection"
  ];

  runTest = name: ''
    if ! cargo test --frozen --offline -p terrane-core --test control_vectors ${name} -- --exact \
      > "$TMPDIR/control-model-test.log" 2>&1; then
      cat "$TMPDIR/control-model-test.log"
      exit 1
    fi
    python3 -c 'import pathlib, sys; output = pathlib.Path(sys.argv[1]).read_text(); print(output); sys.exit("test result: ok. 1 passed; 0 failed; 0 ignored" not in output)' "$TMPDIR/control-model-test.log"
  '';
in
  sourceGate "control-reference-models" ''
    cd crates
    if ! test -f ../tests/terrane/control_vectors.py || ! test -f ../tests/terrane/control-models.rs || ! test -d ../tests/terrane/control_models; then
      printf 'Independent publication and control-record field alternatives remain pending.\n' >&2
      exit 1
    fi
    cargo build --frozen --offline -p terrane-core --example reference_blake3
    reference_binary="$CARGO_TARGET_DIR/debug/examples/reference_blake3"
    python3 ../tests/terrane/control_vectors.py --self-check \
      --blake3-bin "$reference_binary" > "$out/reference-result"
    python3 ../tests/terrane/control_vectors.py --check ../docs/rfcs/0024-terrane/spec/reference/golden-vectors.md \
      --blake3-bin "$reference_binary" >> "$out/reference-result"
    cp ../docs/rfcs/0024-terrane/spec/reference/golden-vectors.md ../tests/terrane/control-reference.md
    cp ../tests/terrane/control-reference.md "$out/reference.md"
    cp ../tests/terrane/control-models.rs terrane-core/tests/control_vectors.rs
    cp -r ../tests/terrane/control_models terrane-core/tests/control_models
    cargo fmt --all -- --check
    ${builtins.concatStringsSep "\n" (map runTest tests)}
    cargo clippy --frozen --offline -p terrane-core --test control_vectors -- -D warnings
    printf 'PASS: independent publication/control alternatives and six exact owning-codec groups\n' > "$out/result"
  ''
