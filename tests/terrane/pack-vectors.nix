{sourceGate}: let
  cases = [
    "published_pack_matches_independent_bytes_and_model"
    "published_detached_index_matches_independent_bytes_and_model"
    "published_pack_rejects_corrupt_index_crc"
    "published_pack_rejects_reserved_index_bytes"
  ];

  runCase = name: ''
    cargo test --frozen --offline -p terrane-core --test pack_vectors ${name} \
      -- --exact > "$TMPDIR/pack-vector-test.log"
    python3 - "$TMPDIR/pack-vector-test.log" <<'PYTEST'
    import pathlib
    import sys

    output = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
    print(output)
    if "test result: ok. 1 passed; 0 failed; 0 ignored" not in output:
        raise SystemExit("each required pack vector case must execute exactly once")
    PYTEST
  '';
in
  sourceGate "pack-format-vectors" ''
    cd crates
    cargo build --frozen --offline -p terrane-core --example reference_blake3
    cd ..
    python3 tests/terrane/pack_vectors.py --check \
      --blake3-bin "$CARGO_TARGET_DIR/debug/examples/reference_blake3" \
      docs/rfcs/0024-terrane/spec/reference/golden-vectors.md
    cd crates
    ${builtins.concatStringsSep "\n" (map runCase cases)}
    printf 'PASS: independent two-entry pack and index reference witnesses\n' > "$out/result"
  ''
