# Checks domain reachability before committed-index lookup, without content I/O.
{sourceGate}: let
  tests = [
    "scoped_indexed_presence_filters_unreachable_hashes_before_index_query"
    "scoped_indexed_presence_bounds_empty_root_only_and_foreign_requests"
    "scoped_indexed_presence_rejects_short_long_and_failed_index_replies"
    "scoped_indexed_presence_accepts_maximum_request_order_and_duplicates"
  ];
  selectors = map (name: "domain::indexed_presence_tests::${name}") tests;
in
  sourceGate "scoped-indexed-presence" ''
    cd crates
    cargo test --frozen --offline -p terrane-sdk --features tokio --lib \
      --no-run --message-format=json > "$out/build.jsonl"
    cargo test --frozen --offline -p terrane-sdk --features tokio --lib \
      -- --list > "$out/inventory.log"
    python3 ../tests/terrane/check_native_gate.py inventory \
      "$out/inventory.log" '${builtins.toJSON selectors}'

    for test_name in ${builtins.concatStringsSep " " selectors}; do
      if ! timeout 30s cargo test --frozen --offline -p terrane-sdk \
        --features tokio --lib "$test_name" -- --exact \
        > "$out/$test_name.log" 2>&1; then
        cat "$out/$test_name.log"
        exit 1
      fi
      python3 ../tests/terrane/check_native_gate.py execution \
        "$out/$test_name.log" "[\"$test_name\"]"
    done

    printf 'PASS: scoped index routing (4 exact in-memory cases)\n' > "$out/result"
  ''
