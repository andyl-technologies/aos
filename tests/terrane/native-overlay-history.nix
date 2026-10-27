{sourceGate}: let
  selectors = [
    "guard::overlay_history::tests::overlay_history_borrows_historical_layer_and_shares_only_one_walk"
    "guard::overlay_history::tests::scope::overlay_history_refuses_foreign_holder_resolver_configuration_and_ordinary_scope"
    "guard::overlay_history::tests::scope::overlay_history_rechecks_current_read_after_revocation"
    "guard::overlay_history::tests::scope::overlay_history_captured_invocations_cannot_exchange_purpose_or_reader"
    "guard::overlay_history::tests::physical::overlay_history_refuses_late_original_and_equal_byte_pack_replacement"
    "guard::overlay_history::tests::physical::overlay_history_native_closing_decline_never_promotes_completion"
    "guard::overlay_history::tests::cancellation::overlay_history_cancelled_close_keeps_namespace_and_original_exclusions"
  ];
  runCases = import ./_native-cases.nix {
    label = "native-overlay-history";
    inherit selectors;
  };
in
  sourceGate "native-overlay-history" ''
    ${runCases}
    printf 'PASS: seven exact borrowed overlay history cases\n' > "$out/result"
  ''
