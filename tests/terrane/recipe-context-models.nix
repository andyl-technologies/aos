{sourceGate}: let
  consumers = [
    {
      template = "domain.rs";
      source = "algebra/domain.rs";
    }
    {
      template = "trust.rs";
      source = "algebra/trust.rs";
    }
  ];

  tests = [
    "algebra::domain::published_witnesses::reference_recipe_domains_preserve_nonempty_fields"
    "algebra::domain::published_witnesses::reference_recipe_domain_negatives_require_structural_rejection"
    "algebra::trust::published_witnesses::reference_recipe_trust_preserves_outer_evidence_fields"
    "algebra::trust::published_witnesses::reference_recipe_trust_negatives_require_structural_rejection"
  ];

  prepare = consumer: ''
    template="$PWD/../tests/terrane/recipe_context_models/${consumer.template}"
    source="terrane-core/src/${consumer.source}"
    if ! test -f "$template" || ! test -f "$source"; then
      printf 'Independent outer recipe field consumers remain pending.\n' >&2
      exit 1
    fi
    printf '\n#[cfg(test)]\n#[path = "%s"]\nmod published_witnesses;\n' "$template" >> "$source"
  '';

  runTest = name: ''
    if ! cargo test --frozen --offline -p terrane-core --lib ${name} -- --exact \
      > "$TMPDIR/recipe-context-model-test.log" 2>&1; then
      cat "$TMPDIR/recipe-context-model-test.log"
      exit 1
    fi
    python3 -c 'import pathlib, sys; output = pathlib.Path(sys.argv[1]).read_text(); print(output); sys.exit("test result: ok. 1 passed; 0 failed; 0 ignored" not in output)' "$TMPDIR/recipe-context-model-test.log"
  '';
in
  sourceGate "recipe-context-reference-models" ''
    cd crates
    if ! test -f ../tests/terrane/recipe_context_vectors.py; then
      printf 'Independent outer recipe reference generator remains pending.\n' >&2
      exit 1
    fi
    ${builtins.concatStringsSep "\n" (map prepare consumers)}
    cargo build --frozen --offline -p terrane-core --example reference_blake3
    reference_binary="$CARGO_TARGET_DIR/debug/examples/reference_blake3"
    python3 ../tests/terrane/recipe_context_vectors.py --self-check \
      --blake3-bin "$reference_binary" > "$out/reference-result"
    python3 ../tests/terrane/recipe_context_vectors.py --check ../docs/rfcs/0024-terrane/spec/reference/golden-vectors.md \
      --blake3-bin "$reference_binary" >> "$out/reference-result"
    cp ../docs/rfcs/0024-terrane/spec/reference/golden-vectors.md ../tests/terrane/recipe-context-reference.md
    cp ../tests/terrane/recipe-context-reference.md "$out/reference.md"
    cargo fmt --all -- --check
    ${builtins.concatStringsSep "\n" (map runTest tests)}
    cargo clippy --frozen --offline -p terrane-core --lib --tests -- -D warnings
    printf 'PASS: ordinary outer recipe fields and four exact pure codec groups\n' > "$out/result"
  ''
