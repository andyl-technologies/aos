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
    cargo test --frozen --offline -p terrane-core --test format_properties \
      > "$TMPDIR/format-properties.log"
    python3 - "$TMPDIR/format-properties.log" <<'PYTEST'
    import pathlib
    import re
    import sys

    output = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
    print(output)
    if not re.search(r"test result: ok\. [1-9][0-9]* passed; 0 failed; 0 ignored", output):
        raise SystemExit("format property suite must execute without failures or ignored cases")
    PYTEST
    # Signature omission encoders have no standalone public record decoder.
    # Their private unit properties must execute alongside the public corpus.
    ${runUnit "auth::tests::format_properties::authority_preimages_match_unsigned_models_and_omit_only_signature"}
    ${runUnit "auth::tests::format_properties::attenuation_preimages_match_unsigned_models_for_every_caveat_and_presence"}
    printf 'PASS: pure format fuzz and property corpus\n' > "$out/result"
  '';
}
