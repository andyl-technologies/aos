{sourceGate}: let
  tests = [
    "published_manifest_matches_separately_constructed_model_and_identity"
    "published_commit_matches_separately_constructed_model_and_identity"
    "published_token_matches_separately_constructed_model_and_identity"
    "published_ref_matches_separately_constructed_model"
    "published_reflog_matches_separately_constructed_model"
    "published_attribute_matches_separately_constructed_model_and_identity"
    "published_bundle_matches_separately_constructed_model_and_identity"
    "published_capabilities_match_separately_constructed_model"
    "published_generation_manifests_match_separately_constructed_models"
    "published_gc_tombstone_matches_separately_constructed_model"
    "published_creation_journals_match_separately_constructed_phase_models"
    "published_local_retirement_records_match_separately_constructed_models"
  ];

  runTest = name: ''
    if ! cargo test --frozen --offline -p terrane-core --test legacy_vectors ${name} -- --exact \
      > "$TMPDIR/legacy-model-test.log" 2>&1; then
      cat "$TMPDIR/legacy-model-test.log"
      exit 1
    fi
    python3 -c 'import pathlib, sys; output = pathlib.Path(sys.argv[1]).read_text(); print(output); sys.exit("test result: ok. 1 passed; 0 failed; 0 ignored" not in output)' "$TMPDIR/legacy-model-test.log"
  '';
in
  sourceGate "legacy-format-vectors" ''
    cd crates
    cargo fmt --all -- --check
    ${builtins.concatStringsSep "\n" (map runTest tests)}
    if ! cargo test --frozen --offline -p terrane-core --lib \
      auth::tests::legacy_vectors::published_token_private_fields_match_separately_constructed_model -- --exact \
      > "$TMPDIR/legacy-token-test.log" 2>&1; then
      cat "$TMPDIR/legacy-token-test.log"
      exit 1
    fi
    python3 -c 'import pathlib, sys; output = pathlib.Path(sys.argv[1]).read_text(); print(output); sys.exit("test result: ok. 1 passed; 0 failed; 0 ignored" not in output)' "$TMPDIR/legacy-token-test.log"
    cargo clippy --frozen --offline -p terrane-core --all-targets -- -D warnings
    printf 'PASS: twelve exact public legacy groups and one complete private token-model group\n' > "$out/result"
  ''
