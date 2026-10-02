{sourceGate}: let
  tests = [
    "published_collection_lease_matches_bytes_and_model"
    "published_collection_roots_preserve_every_reason_and_cutoff"
    "published_collection_marks_reconstruct_exact_hints"
    "published_collection_states_preserve_phases_and_fieldwise_contexts"
    "published_collection_tombstone_matches_bytes_and_model"
    "published_collection_generations_distinguish_unknown_and_known_empty"
  ];

  runTest = name: ''
    cargo test --frozen --offline -p terrane-core --test collection_vectors ${name} -- --exact \
      > "$TMPDIR/collection-vector-test.log"
    python3 -c 'import pathlib, sys; output = pathlib.Path(sys.argv[1]).read_text(); print(output); sys.exit("test result: ok. 1 passed; 0 failed; 0 ignored" not in output)' "$TMPDIR/collection-vector-test.log"
  '';
in
  sourceGate "collection-format-vectors" ''
    cd crates
    python3 ../tests/terrane/collection_vectors.py --check \
      ../docs/rfcs/0024-terrane/spec/reference/golden-vectors.md > "$out/reference-result"
    ${builtins.concatStringsSep "\n" (map runTest tests)}
    printf 'PASS: 20 independent collection vectors and six exact model tests\n' > "$out/result"
  ''
