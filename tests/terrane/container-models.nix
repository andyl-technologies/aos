{sourceGate}: let
  tests = [
    "reference_chunk_envelope_models_preserve_codec_body_and_dictionary_fields"
    "reference_merged_shard_models_preserve_record_fields_and_states"
    "reference_negative_container_wires_require_structural_rejection"
  ];

  runTest = name: ''
    if ! cargo test --frozen --offline -p terrane-core --test container_vectors ${name} -- --exact \
      > "$TMPDIR/container-model-test.log" 2>&1; then
      cat "$TMPDIR/container-model-test.log"
      exit 1
    fi
    python3 -c 'import pathlib, sys; output = pathlib.Path(sys.argv[1]).read_text(); print(output); sys.exit("test result: ok. 1 passed; 0 failed; 0 ignored" not in output)' "$TMPDIR/container-model-test.log"
  '';
in
  sourceGate "container-reference-models" ''
    cd crates
    if ! test -f ../tests/terrane/container_vectors.py || ! test -f ../tests/terrane/container-models.rs; then
      printf 'Chunk envelope and merged-shard reference models remain pending implementation.\n' >&2
      exit 1
    fi
    cargo build --frozen --offline -p terrane-core --example reference_blake3
    reference_binary="$CARGO_TARGET_DIR/debug/examples/reference_blake3"
    python3 ../tests/terrane/container_vectors.py --self-check \
      --blake3-bin "$reference_binary" > "$out/reference-result"
    python3 ../tests/terrane/container_vectors.py --emit \
      --blake3-bin "$reference_binary" > ../tests/terrane/container-reference.md
    python3 ../tests/terrane/container_vectors.py --check ../tests/terrane/container-reference.md \
      --blake3-bin "$reference_binary" >> "$out/reference-result"
    cp ../tests/terrane/container-reference.md "$out/reference.md"
    cp ../tests/terrane/container-models.rs terrane-core/tests/container_vectors.rs
    cargo fmt --all -- --check
    ${builtins.concatStringsSep "\n" (map runTest tests)}
    cargo clippy --frozen --offline -p terrane-core --test container_vectors -- -D warnings
    printf 'PASS: independent envelope and merged-shard models with three exact owning-codec groups\n' > "$out/result"
  ''
