{
  sourceGate,
  ...
}: {
  store-error-taxonomy = sourceGate "store-error-taxonomy" ''
    cd crates
    cargo test --frozen --offline -p terrane --lib store::tests::error_outcomes_preserve_sources_without_changing_category
    cargo test --frozen --offline -p terrane --lib store::tests::conflict_and_existing_log_are_distinct_from_backend_failure
    printf 'PASS: store outcomes and chained diagnostics\n' > "$out/result"
  '';

  store-trait-split = sourceGate "store-trait-split" ''
    cd crates
    cargo test --frozen --offline -p terrane --lib store::tests::ref_capabilities_distinguish_authority_from_cache
    cargo test --frozen --offline -p terrane --doc
    printf 'PASS: content and ref interfaces remain distinct\n' > "$out/result"
  '';

  runtime-agnostic = sourceGate "runtime-agnostic" ''
    cd crates
    cargo check --frozen --offline -p terrane --lib --no-default-features
    cargo check --frozen --offline -p terrane --lib --no-default-features --features std,send
    cargo test --frozen --offline -p terrane --lib --no-default-features --features wasm store::tests::wasm_binding_forwards_fetch_and_host_time
    cargo check --frozen --offline -p terrane --lib --features tokio
    cargo test --frozen --offline -p terrane --lib --features tokio store::tests::native_create_new_preserves_existing_bytes
    printf 'PASS: portable store traits and native binding compile\n' > "$out/result"
  '';
}
