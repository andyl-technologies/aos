{sourceGate}: let
  tests = [
    "separate_invocations_initialize_commit_fork_merge_and_checkout"
    "local_commands_refuse_reinitialization_and_unsafe_existing_authority"
    "configured_role_parser_and_unavailable_dispatch_remain_compatible"
    "local_log_reports_committed_provenance_and_honors_sequence_filter"
    "local_diff_reports_quoted_changes_stats_and_refuses_unauthorized_output"
    "local_blame_preserves_introduction_through_merges_and_refuses_unauthorized_output"
  ];
in
  sourceGate "local-cli-workflow" ''
    cd crates
    cargo test --frozen --offline -p terrane-cli --test local_cli \
      --no-run --message-format=json > "$out/build.jsonl"
    cargo test --frozen --offline -p terrane-cli --test local_cli \
      -- --list > "$out/inventory.log"
    python3 ../tests/terrane/check_native_gate.py inventory \
      "$out/inventory.log" '${builtins.toJSON tests}'
    for test_name in ${builtins.concatStringsSep " " tests}; do
      if ! cargo test --frozen --offline -p terrane-cli --test local_cli \
        "$test_name" -- --exact > "$out/$test_name.log" 2>&1; then
        cat "$out/$test_name.log"
        exit 1
      fi
      python3 ../tests/terrane/check_native_gate.py execution \
        "$out/$test_name.log" "[\"$test_name\"]"
    done
    printf 'PASS: public local CLI workflow (6 exact cases); ext4 deployment remains separate\n' \
      > "$out/result"
  ''
