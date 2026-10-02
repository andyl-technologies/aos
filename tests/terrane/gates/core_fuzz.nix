{sourceGate, ...}: {
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
    printf 'PASS: pure format fuzz and property corpus\n' > "$out/result"
  '';
}
