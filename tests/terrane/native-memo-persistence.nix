{sourceGate}: let
  names = [
    "common_memo_persists_and_reopens_all_t1_outputs"
    "common_memo_optional_loss_preserves_disabled_results"
    "common_memo_divergence_refuses_until_complete_persisted_rebuild"
    "common_memo_replay_preserves_actual_current_original_and_trust_checks"
    "overlay::native_nested_overlay_reopens_closure_and_rechecks_policy"
  ];
  selectors = map (name: "derivation::tests::native::${name}") names;
  runCases = import ./_native-cases.nix {
    label = "native-memo-persistence";
    inherit selectors;
  };
in
  # This leaf reuses the common replay and does not certify root-associated GC.
  sourceGate "native-memo-persistence" ''
    ${runCases}
    printf 'PASS: five exact native common Memo persistence prerequisites\n' > "$out/result"
  ''
