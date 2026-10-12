{sourceGate}: let
  names = [
    "native_index_lookup_matches_sha256_and_deduplicates_authorized_occurrences"
    "native_index_lookup_filters_current_acl_trust_and_producer_context"
    "native_index_lookup_reports_gaps_even_when_candidate_range_is_empty"
    "native_index_lookup_selects_fallback_only_without_owner_binding"
    "native_index_lookup_rechecks_held_current_controls_before_return"
    "native_index_lookup_separates_loading_validation_candidates_occurrences_and_current_work"
  ];
  selectors = map (name: "guard::read::indexes::tests::${name}") names;
  runCases = import ./_native-cases.nix {
    label = "native-index-lookup";
    inherit selectors;
  };
in
  # Indexed candidates remain data until actual current checks produce answers.
  sourceGate "native-index-lookup" ''
    ${runCases}
    printf 'PASS: six exact native authorized index-lookup prerequisites\n' > "$out/result"
  ''
