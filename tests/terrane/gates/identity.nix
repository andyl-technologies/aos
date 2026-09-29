{sourceGate, ...}: {
  identity-idempotence = sourceGate "identity-idempotence" ''
    cd crates
    cargo test --frozen --offline -p terrane-core --lib \
      identity::tests::chunk_identity_matches_both_golden_vectors
    cargo test --frozen --offline -p terrane-core --lib \
      identity::tests::every_immutable_kind_has_a_distinct_registered_domain
    cargo test --frozen --offline -p terrane-core --lib \
      identity::tests::a_second_profile_cannot_reinterpret_initial_identities
    printf 'PASS: registered domains and profile-bound identities\n' > "$out/result"
  '';

  descriptor-strict = sourceGate "descriptor-strict" ''
    cd crates
    cargo test --frozen --offline -p terrane-core --lib \
      identity::tests::descriptor_rejects_mismatched_fields_and_bytes
    printf 'PASS: descriptor algorithm, domain, size, and digest validation\n' > "$out/result"
  '';
}
