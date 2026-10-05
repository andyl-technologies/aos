{sourceGate, ...}: let
  # Cargo succeeds when a filter matches nothing, so require the exact test
  # before executing a focused conformance check.
  focusedTest = ''
    run_store_test() {
      test_name=$1
      shift
      cargo test --frozen --offline -p terrane --lib "$@" -- --list > "$TMPDIR/store-tests.txt"
      python3 - "$TMPDIR/store-tests.txt" "$test_name" <<'PYTEST'
    import sys

    with open(sys.argv[1], encoding="utf-8") as test_list:
        names = {line.strip() for line in test_list}

    if f"{sys.argv[2]}: test" not in names:
        raise SystemExit(f"required store test is missing: {sys.argv[2]}")
    PYTEST
      cargo test --frozen --offline -p terrane --lib "$@" "$test_name" -- --exact
    }
  '';
in {
  store-error-taxonomy = sourceGate "store-error-taxonomy" ''
    cd crates
    ${focusedTest}
    run_store_test store::tests::error_outcomes_preserve_sources_without_changing_category
    run_store_test store::tests::invalid_diagnostics_preserve_upload_and_range_context
    run_store_test store::tests::conflict_and_existing_log_are_distinct_from_backend_failure
    printf 'PASS: store outcomes and chained diagnostics\n' > "$out/result"
  '';

  store-trait-split = sourceGate "store-trait-split" ''
    cd crates
    ${focusedTest}
    run_store_test store::tests::content_only_cache_implements_no_ref_authority
    cargo test --frozen --offline -p terrane --doc
    printf 'PASS: content and ref interfaces remain distinct\n' > "$out/result"
  '';

  runtime-agnostic = sourceGate "runtime-agnostic" ''
    cd crates
    ${focusedTest}
    cargo check --frozen --offline -p terrane --lib --no-default-features
    cargo check --frozen --offline -p terrane --lib --no-default-features --features std,send
    run_store_test store::tests::wasm_binding_forwards_fetch_and_separates_wall_from_elapsed_time --no-default-features --features wasm
    cargo check --frozen --offline -p terrane --lib --features tokio
    cargo check --frozen --offline -p terrane --lib --no-default-features --features std,wasm
    run_store_test store::tests::native_file_binding_preserves_atomic_names_and_ranges --features tokio
    run_store_test store::tests::native_clock_ticks_do_not_move_backward --features tokio
    run_store_test store::bindings::tests::native_timer_waits_and_rejects_duration_overflow --features tokio
    run_store_test store::bindings::tests::native_metadata_preserves_links_permissions_and_nofollow_attributes --features tokio
    run_store_test store::bindings::tests::native_nofollow_sync_rejects_replacement_symlink_and_nonregular_files --features tokio
    run_store_test store::tests::native_http_client_is_send_and_sync --features tokio
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

    for name in ("terrane-cli", "aos-terrane"):
        dependency = next(dep for dep in packages[name]["dependencies"] if dep["name"] == "terrane")
        bindings = set(dependency["features"]) & {"tokio", "wasm"}
        if bindings != {"tokio"}:
            raise SystemExit(f"{name} must select exactly the native I/O binding: {bindings}")

    for name in sorted(selected):
        for feature in sorted(packages[name]["features"]):
            print(name, feature)
    PY

        test_crate() {
          package_name=$1
          shift
          if [ "$package_name" = terrane-cli ]; then
            cargo test --frozen --offline -p "$package_name" --bin terrane "$@"
          elif [ "$package_name" = terrane ]; then
            # Independent native fixtures have real operation deadlines. Bound
            # their fanout; each fixture still runs its own competing writers.
            cargo test --frozen --offline -p "$package_name" --lib "$@" -- --test-threads=1
          else
            cargo test --frozen --offline -p "$package_name" --lib "$@"
          fi
        }

        for crate in terrane-core terrane terrane-fs terrane-cli aos-terrane; do
          test_crate "$crate" --no-default-features
          if [ "$crate" = terrane ]; then
            test_crate "$crate" --no-default-features --features std,send,tokio
            test_crate "$crate" --no-default-features --features std,wasm
          else
            test_crate "$crate" --all-features
          fi
        done

        while read -r crate feature; do
          test_crate "$crate" --no-default-features --features "$feature"
        done < "$TMPDIR/terrane-features.tsv"

        # These configurations violate the binding contract. Check the
        # intentional diagnostic so an unrelated compiler error cannot pass.
        for features in tokio,wasm wasm,send; do
          if cargo check --frozen --offline -p terrane --lib --no-default-features --features "$features" > "$TMPDIR/incompatible.txt" 2>&1; then
            printf 'incompatible I/O features compiled: %s\n' "$features" >&2
            exit 1
          fi
          python3 - "$TMPDIR/incompatible.txt" "$features" <<'PY'
    import sys

    expected = "CRATE-8:" if sys.argv[2] == "tokio,wasm" else "CRATE-7:"
    with open(sys.argv[1], encoding="utf-8") as diagnostics:
        if expected not in diagnostics.read():
            raise SystemExit(f"missing intentional binding rejection: {sys.argv[2]}")
    PY
        done

        cargo test --frozen --offline -p terrane --no-default-features --features tokio --doc
        cargo test --frozen --offline -p terrane --no-default-features --features wasm --doc
        printf 'PASS: declared Terrane features build and test on the native target\n' > "$out/result"
  '';
}
