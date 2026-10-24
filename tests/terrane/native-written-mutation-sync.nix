{sourceGate}: let
  tests = [
    "written_mutation_syncs_exact_outputs_and_unique_directories"
    "written_mutation_syncs_unchanged_projection_repair"
    "written_mutation_syncs_removed_projection_cache_directory"
    "written_mutation_syncs_newly_created_projection_directories"
    "written_mutation_retains_unsynchronized_history_preimages"
    "written_mutation_retains_unsynchronized_source_lineage_preimage"
  ];
  selectors = map (name: "ref_advance::fault_tests::mutation_ack::write_set::${name}") tests;
  runCases = import ./_native-cases.nix {
    label = "native-written-mutation-sync";
    inherit selectors;
  };
in
  sourceGate "native-written-mutation-sync" ''
    ${runCases}
    printf 'PASS: actual written mutation durability (6 exact cases)\n' > "$out/result"
  ''
