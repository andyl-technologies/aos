{sourceGate}: let
  tests = [
    "waits::full_d_with_multiple_real_renewals_reaches_invalidated"
    "waits::early_and_expired_wait_never_create_authorized"
    "waits::regression_or_changed_incarnation_discards_wait"
    "waits::renewal_failure_and_dropped_wait_poison_session"
    "ownership::authorized_and_each_owner_sync_fault_preserve_exact_partial_prefix"
    "ownership::fresh_current_authority_required_before_each_ownership_effect"
  ];
  selectors = map (name: "gc::runner::tests::local_ownership::${name}") tests;
  runCases = import ./_native-cases.nix {
    label = "native-local-first-ownership";
    inherit selectors;
  };
in
  sourceGate "native-local-first-ownership" ''
    ${runCases}
    printf 'PASS: ordinary local first ownership (6 exact cases); unlink/recovery/cancellation remain separate\n' \
      > "$out/result"
  ''
