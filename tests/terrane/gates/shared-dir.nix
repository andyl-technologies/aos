{
  nativeSdkGate,
  portableSharedModes,
  ...
}: let
  native = label: names:
    import ../_native-cases.nix {
      inherit label;
      selectors = map (name: "store::shared_dir::native_tests::${name}") names;
    };
in {
  shared-dir-read-only = nativeSdkGate "shared-dir-read-only" ''
    ${native "shared-dir-read-only" [
      "existing_directory_reads_and_rejected_puts_leave_bytes_and_names_unchanged"
      "corrupt_existing_chunk_is_never_returned_or_repaired"
      "explicit_read_budget_returns_capacity_without_mutating_valid_content"
      "exact_encoded_ranges_verify_the_complete_chunk_before_returning_bytes"
      "manifest_get_returns_canonical_metadata_instead_of_sealed_plaintext"
      "residence_composition::portable_composition_recovers_encoded_chunk_after_ordinary_body_removal"
      "residence_composition::portable_residence_never_masks_corruption_or_substitutes_manifest_plaintext"
    ]}
    test "$(cat ${portableSharedModes}/result)" = PASS
    mkdir -p "$out/nix-support"
    printf '%s\n' ${portableSharedModes} > "$out/nix-support/shared-modes-proof"
    printf 'PASS: actual existing host reads preserve encoded bytes and never write\n' > "$out/result"
  '';

  dom-host-isolation = nativeSdkGate "dom-host-isolation" ''
    ${native "dom-host-isolation" [
      "domain_routes_never_probe_another_directory_or_unreachable_identity"
      "same_domain_snapshots_read_one_existing_inode_without_extending_reachability"
      "routes_refuse_two_domain_labels_for_the_same_directory"
      "directory_and_body_symlinks_cannot_cross_domain_boundaries"
      "shared_private_open_refuses_before_touching_missing_root"
      "residence_composition::portable_resident_routes_preserve_domain_and_reachability_before_lookup"
    ]}
    printf 'PASS: independent scoped directory routes and private-cache refusal\n' > "$out/result"
  '';
}
