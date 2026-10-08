{sourceGate}: let
  tests = [
    "published_common_memos_match_independent_fields_bytes_and_record_identities"
    "published_common_memo_negatives_reproduce_independent_wires_and_are_rejected"
    "published_foundation_memo_payload_decodes_as_the_common_record"
  ];

  runTest = name: ''
    if ! cargo test --frozen --offline -p terrane-core --test memo_vectors ${name} -- --exact \
      > "$TMPDIR/memo-vector-test.log" 2>&1; then
      cat "$TMPDIR/memo-vector-test.log"
      exit 1
    fi
    python3 -c 'import pathlib, sys; output = pathlib.Path(sys.argv[1]).read_text(); print(output); sys.exit("test result: ok. 1 passed; 0 failed; 0 ignored" not in output)' "$TMPDIR/memo-vector-test.log"
  '';
in
  sourceGate "memo-format-vectors" ''
    cd crates
    if ! test -f ../tests/terrane/memo_vectors.py || ! test -f terrane-core/tests/memo_vectors.rs; then
      printf 'Published common Memo decoder witnesses remain pending.\n' >&2
      exit 1
    fi
    cargo build --frozen --offline -p terrane-core --example reference_blake3
    reference_binary="$CARGO_TARGET_DIR/debug/examples/reference_blake3"
    python3 ../tests/terrane/memo_vectors.py --self-check \
      --blake3-bin "$reference_binary" > "$out/reference-result"
    python3 ../tests/terrane/memo_vectors.py --check \
      ../docs/rfcs/0024-terrane/spec/reference/golden-vectors.md \
      --blake3-bin "$reference_binary" >> "$out/reference-result"
    cargo fmt --all -- --check
    ${builtins.concatStringsSep "\n" (map runTest tests)}
    cargo clippy --frozen --offline -p terrane-core --test memo_vectors -- -D warnings
    printf 'PASS: independent common Memo fields, identities and owning decoder witnesses\n' > "$out/result"
  ''
