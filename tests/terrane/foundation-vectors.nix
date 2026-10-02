{sourceGate}: let
  tests = [
    "published_descriptors_match_all_registered_domains_and_payloads"
    "published_nodes_match_separately_constructed_fields_and_identities"
    "published_internal_tree_matches_actual_profile_boundary_and_child_summaries"
  ];

  runTest = name: ''
    if ! cargo test --frozen --offline -p terrane-core --test foundation_vectors ${name} -- --exact \
      > "$TMPDIR/foundation-model-test.log" 2>&1; then
      cat "$TMPDIR/foundation-model-test.log"
      exit 1
    fi
    python3 -c 'import pathlib, sys; output = pathlib.Path(sys.argv[1]).read_text(); print(output); sys.exit("test result: ok. 1 passed; 0 failed; 0 ignored" not in output)' "$TMPDIR/foundation-model-test.log"
  '';
in
  sourceGate "foundation-format-vectors" ''
    cd crates
    cargo build --frozen --offline -p terrane-core --example reference_blake3
    reference_binary="$CARGO_TARGET_DIR/debug/examples/reference_blake3"
    python3 ../tests/terrane/foundation_vectors.py --check \
      ../docs/rfcs/0024-terrane/spec/reference/golden-vectors.md \
      --blake3-bin "$reference_binary" > "$out/reference-result"
    cargo fmt --all -- --check
    ${builtins.concatStringsSep "\n" (map runTest tests)}
    cargo clippy --frozen --offline -p terrane-core --test foundation_vectors -- -D warnings
    printf 'PASS: fifteen independent models and three exact public-model tests\n' > "$out/result"
  ''
