{sourceGate, ...}: let
  runUnit = path: ''
    cargo test --frozen --offline -p terrane-core --lib ${path} -- --exact \
      > "$TMPDIR/format-unit.log"
    python3 -c 'import pathlib, sys; output = pathlib.Path(sys.argv[1]).read_text(); print(output); sys.exit("test result: ok. 1 passed; 0 failed; 0 ignored" not in output)' "$TMPDIR/format-unit.log"
  '';
in {
  # The integration target is deliberately required before this gate can pass.
  # Its pure, deterministic corpus covers format properties without store I/O.
  core-fuzz = sourceGate "core-fuzz" ''
    cd crates
    cargo test --frozen --offline -p terrane-core --test format_properties -- --list \
      > "$TMPDIR/format-properties-inventory.log"
    python3 ../tests/terrane/format_property_inventory.py \
      ../tests/terrane/format-properties.expected \
      --inventory "$TMPDIR/format-properties-inventory.log"
    cargo test --frozen --offline -p terrane-core --test format_properties \
      > "$TMPDIR/format-properties.log"
    python3 ../tests/terrane/format_property_inventory.py \
      ../tests/terrane/format-properties.expected \
      --execution "$TMPDIR/format-properties.log"
    # Signature omission encoders have no standalone public record decoder.
    # Their private unit properties must execute alongside the public corpus.
    ${runUnit "auth::tests::format_properties::authority_preimages_match_unsigned_models_and_omit_only_signature"}
    ${runUnit "auth::tests::format_properties::attenuation_preimages_match_unsigned_models_for_every_caveat_and_presence"}
    ${runUnit "provenance::disclosure::statement::tests::disclosure_statement_models_retain_every_registered_field"}
    ${runUnit "provenance::trust::encoding::tests::context_models_preserve_versions_presence_and_selected_bytes"}
    ${runUnit "provenance::side_attributes::serialization::tests::selected_evidence_models_preserve_tuple_fields_and_filtered_row_order"}
    printf 'PASS: pure format fuzz and property corpus\n' > "$out/result"
  '';
}
