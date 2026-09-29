{sourceGate, ...}: {
  store-error-taxonomy = sourceGate "store-error-taxonomy" ''
    cd crates
    cargo test --frozen --offline -p terrane --lib store::tests::error_outcomes_preserve_sources_without_changing_category
    cargo test --frozen --offline -p terrane --lib store::tests::invalid_diagnostics_preserve_upload_and_range_context
    cargo test --frozen --offline -p terrane --lib store::tests::conflict_and_existing_log_are_distinct_from_backend_failure
    printf 'PASS: store outcomes and chained diagnostics\n' > "$out/result"
  '';

  store-trait-split = sourceGate "store-trait-split" ''
    cd crates
    cargo test --frozen --offline -p terrane --lib store::tests::content_only_cache_implements_no_ref_authority
    cargo test --frozen --offline -p terrane --doc
    printf 'PASS: content and ref interfaces remain distinct\n' > "$out/result"
  '';

  runtime-agnostic = sourceGate "runtime-agnostic" ''
    cd crates
    cargo check --frozen --offline -p terrane --lib --no-default-features
    cargo check --frozen --offline -p terrane --lib --no-default-features --features std,send
    cargo test --frozen --offline -p terrane --lib --no-default-features --features wasm store::tests::wasm_binding_forwards_fetch_and_separates_wall_from_elapsed_time
    cargo check --frozen --offline -p terrane --lib --features tokio
    cargo check --frozen --offline -p terrane --lib --all-features
    cargo test --frozen --offline -p terrane --lib --features tokio store::tests::native_file_binding_preserves_atomic_names_and_ranges
    cargo test --frozen --offline -p terrane --lib --features tokio store::tests::native_clock_ticks_do_not_move_backward
    cargo test --frozen --offline -p terrane --lib --features tokio store::tests::native_http_client_is_send_and_sync
    printf 'PASS: portable store traits and native binding compile\n' > "$out/result"
  '';

  feature-matrix = sourceGate "feature-matrix" ''
        cd crates
        # This milestone supports native Linux. Extend the target matrix when
        # the edge host becomes a supported build target.
        cargo metadata --no-deps --frozen --offline --format-version 1 > "$TMPDIR/terrane-matrix.json"
        python3 - "$TMPDIR/terrane-matrix.json" > "$TMPDIR/terrane-features.tsv" <<'PY'
    import json
    import sys

    selected = {"terrane-core", "terrane", "terrane-fs", "terrane-cli", "aos-terrane"}
    with open(sys.argv[1], encoding="utf-8") as metadata_file:
        metadata = json.load(metadata_file)

    packages = {package["name"]: package for package in metadata["packages"]}
    if not selected <= packages.keys():
        raise SystemExit(f"missing Terrane crates: {sorted(selected - packages.keys())}")

    for name in sorted(selected):
        for feature in sorted(packages[name]["features"]):
            print(name, feature)
    PY

        test_crate() {
          package_name=$1
          shift
          if [ "$package_name" = terrane-cli ]; then
            cargo test --frozen --offline -p "$package_name" --bin terrane "$@"
          else
            cargo test --frozen --offline -p "$package_name" --lib "$@"
          fi
        }

        for crate in terrane-core terrane terrane-fs terrane-cli aos-terrane; do
          test_crate "$crate" --no-default-features
          test_crate "$crate" --all-features
        done

        while read -r crate feature; do
          test_crate "$crate" --no-default-features --features "$feature"
        done < "$TMPDIR/terrane-features.tsv"

        # Both features may be compiled for a matrix build; each I/O consumer
        # selects one binding, and the wasm adapter excludes Send futures.
        cargo test --frozen --offline -p terrane --all-features --doc
        printf 'PASS: declared Terrane features build and test on the native target\n' > "$out/result"
  '';
}
