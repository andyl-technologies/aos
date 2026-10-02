{sourceGate}: let
  publicTests = [
    "published_chunk_identities_match_independent_plaintext_models"
    "published_inline_entry_and_leaf_preserve_complete_models"
    "published_node_boundary_rows_and_item_hash_match_owning_functions"
  ];

  privateTests = [
    "chunking::published_witnesses::published_gear_masks_and_cdc_offsets_match_profile"
    "auth::format::published_witnesses::published_authority_preimage_matches_unsigned_model"
    "auth::format::published_witnesses::published_attenuation_preimage_matches_unsigned_model"
  ];

  consumers = [
    {
      template = "chunking.rs";
      source = "chunking.rs";
    }
    {
      template = "preimages.rs";
      source = "auth/format.rs";
    }
  ];

  prepare = consumer: ''
    template="$PWD/../tests/terrane/prefix_models/${consumer.template}"
    source="terrane-core/src/${consumer.source}"
    if ! test -f "$template" || ! test -f "$source"; then
      printf 'Independent original-prefix field consumers remain pending.\n' >&2
      exit 1
    fi
    printf '\n#[cfg(test)]\n#[path = "%s"]\nmod published_witnesses;\n' "$template" >> "$source"
  '';

  runTest = target: name: ''
    if ! cargo test --frozen --offline -p terrane-core ${target} ${name} -- --exact \
      > "$TMPDIR/prefix-model-test.log" 2>&1; then
      cat "$TMPDIR/prefix-model-test.log"
      exit 1
    fi
    python3 -c 'import pathlib, sys; output = pathlib.Path(sys.argv[1]).read_text(); print(output); sys.exit("test result: ok. 1 passed; 0 failed; 0 ignored" not in output)' "$TMPDIR/prefix-model-test.log"
  '';
in
  sourceGate "prefix-reference-models" ''
    cd crates
    if ! test -f ../tests/terrane/prefix-models.rs; then
      printf 'Independent original-prefix public models remain pending.\n' >&2
      exit 1
    fi
    ${builtins.concatStringsSep "\n" (map prepare consumers)}
    cp ../tests/terrane/prefix-models.rs terrane-core/tests/prefix_vectors.rs
    cp ../docs/rfcs/0024-terrane/spec/reference/golden-vectors.md "$out/reference.md"
    cargo fmt --all -- --check
    ${builtins.concatStringsSep "\n" (map (runTest "--test prefix_vectors") publicTests)}
    ${builtins.concatStringsSep "\n" (map (runTest "--lib") privateTests)}
    cargo clippy --frozen --offline -p terrane-core --lib --tests -- -D warnings
    printf 'PASS: original published chunk, boundary, entry and unsigned-preimage witnesses in six exact groups\n' > "$out/result"
  ''
