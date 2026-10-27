##! Retains an independent offline Cargo build of the registry SPA entry point.
{pkgs}:
pkgs.mkDerivation {
  pname = "aos-bazel-registry-web-browser-cargo-oracle";
  version = "1";
  src = import ../../pkgs/tools/crucible/_cargo-source.nix {inherit (pkgs) lib;};
  buildDeps = [pkgs.rust pkgs.python3 pkgs.sed pkgs.wasm-bindgen-cli];
  sharedBuildCache = false;
  dontStrip = true;
  dontPatchELF = true;
  dontNukeRefs = true;
  phases = [
    {
      name = "compile";
      script = ''
        cp -R "$src" source
        chmod -R u+w source
        cd source
        export CARGO_HOME="$TMPDIR/cargo" CARGO_TARGET_DIR="$TMPDIR/target" CARGO_INCREMENTAL=0
        mkdir -p "$CARGO_HOME" .cargo "$out/dist"
        sed 's|@vendor@|${pkgs.aos.passthru.cargoDeps}|g' \
          ${pkgs.aos.passthru.cargoDeps}/.cargo/config.toml > .cargo/config.toml
        printf '#!${pkgs.python3}/bin/python3\n' > "$TMPDIR/rustc-wrapper"
        cat ${../../tools/bazel/tests/trace_cargo_rustc.py} >> "$TMPDIR/rustc-wrapper"
        chmod +x "$TMPDIR/rustc-wrapper"
        export RUSTC_WRAPPER="$TMPDIR/rustc-wrapper" AOS_CARGO_RUSTC_TRACE="$out/compiler-arguments.jsonl"
        cargo build --frozen --offline --release --manifest-path crates/Cargo.toml \
          -p aos-registry-web --bin aos-registry-spa --target wasm32-unknown-unknown \
          --jobs "$NIX_BUILD_CORES" --message-format=json > "$out/cargo-messages.jsonl" || {
          ${pkgs.python3}/bin/python3 - "$out/cargo-messages.jsonl" <<'PYTHON'
        import json
        from pathlib import Path
        import sys

        for line in Path(sys.argv[1]).read_text().splitlines():
            event = json.loads(line)
            if event.get("reason") == "compiler-message" and event["message"]["level"] == "error":
                print(event["message"].get("rendered") or event["message"]["message"], file=sys.stderr)
        PYTHON
          exit 1
        }
        cp "$CARGO_TARGET_DIR/wasm32-unknown-unknown/release/aos-registry-spa.wasm" "$out/registry-spa.wasm"
        wasm-bindgen --target web --out-dir "$out/dist" --out-name app "$out/registry-spa.wasm"
        cp crates/registry/aos-registry-web/assets/app.css "$out/dist/style.css"
      '';
    }
  ];
}
