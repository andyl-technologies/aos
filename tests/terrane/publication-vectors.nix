{sourceGate}: let
  tests = [
    "gc::publication::cbor::tests::published::published_bindings_and_activation_match_described_models"
    "gc::publication::cbor::tests::published::published_empty_history_preserves_never_and_unknown_distinction"
    "gc::publication::evidence::cbor::tests::published::published_original_and_trust_vectors_match_described_models"
    "gc::publication::evidence::cbor::tests::published::published_guard_and_policy_vectors_match_described_models"
  ];

  # This check proves only the additive D-84 corpus. The registered complete
  # golden-vectors gate stays pending until all normative vectors are covered.
  runTest = name: ''
    cargo test --frozen --offline -p terrane-core --lib ${name} -- --exact > "$TMPDIR/vector-test.log"
    python3 - "$TMPDIR/vector-test.log" <<'PYTEST'
    import pathlib
    import sys

    output = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
    print(output)
    if "test result: ok. 1 passed; 0 failed" not in output:
        raise SystemExit("required published-vector test did not execute successfully")
    PYTEST
  '';
in
  sourceGate "publication-format-vectors" ''
    python3 tests/terrane/publication_vectors.py --check \
      docs/rfcs/0024-terrane/spec/reference/golden-vectors.md > "$out/reference-result"
    cd crates
    ${builtins.concatStringsSep "\n" (map runTest tests)}
    printf 'PASS: 21 independent published D-79 format vectors and four exact model tests\n' \
      > "$out/result"
  ''
