{sourceGate, ...}: let
  runTest = name: ''
    cargo test --frozen --offline -p terrane-core --lib ${name} -- --exact > "$TMPDIR/test.log"
    python3 -c 'import pathlib, sys; output = pathlib.Path(sys.argv[1]).read_text(); print(output); sys.exit("test result: ok. 1 passed; 0 failed" not in output)' "$TMPDIR/test.log"
  '';

  chainTests = ''
    ${runTest "auth::tests::auth_token_chain_golden_preimages_and_signatures"}
    ${runTest "auth::tests::auth_verify_pure_rejects_unknown_retired_keys_time_and_broken_chains"}
    ${runTest "auth::tests::auth_verify_pure_rejects_unknown_noncanonical_truncated_and_oversized_fields"}
    ${runTest "auth::tests::auth_verify_pure_accepts_unbounded_schema_text_and_canonical_root_bytes"}
    ${runTest "auth::tests::auth_verify_pure_effective_expiry_intersects_strict_time_and_retirement"}
    ${runTest "auth::tests::auth_verify_pure_registered_chain_and_grant_limits"}
  '';

  monotoneTests = ''
    ${runTest "auth::tests::auth_attenuation_monotone_rejects_signed_widening"}
    ${runTest "auth::tests::auth_attenuation_monotone_glob_language_and_union_containment"}
    ${runTest "auth::tests::auth_attenuation_monotone_scope_union_and_caveats_survive_append"}
  '';
in {
  auth-token-chain = sourceGate "auth-token-chain" ''
    cd crates
    ${chainTests}
    printf 'PASS: canonical Ed25519 token chains and closed schemas\n' > "$out/result"
  '';

  auth-verify-pure = sourceGate "auth-verify-pure" ''
    cd crates
    cargo build --frozen --offline --no-default-features -p terrane-core --lib
    ${chainTests}
    printf 'PASS: pure no_std signature, issuer, and time verification\n' > "$out/result"
  '';

  auth-attenuation-monotone = sourceGate "auth-attenuation-monotone" ''
    cd crates
    ${monotoneTests}
    printf 'PASS: signed widening rejection and grant union containment\n' > "$out/result"
  '';

  auth-attenuation-offline = sourceGate "auth-attenuation-offline" ''
    cd crates
    ${monotoneTests}
    ${runTest "auth::tests::auth_attenuation_offline_all_caveats_and_literal_verb_masks"}
    printf 'PASS: offline delegation and closed conjunctive caveats\n' > "$out/result"
  '';
}
