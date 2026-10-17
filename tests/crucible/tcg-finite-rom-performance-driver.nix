{
  pkgs,
  lib,
}: let
  src = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = import ./_cargo-deps.nix {inherit pkgs lib;};
in
  pkgs.mkDerivation {
    pname = "crucible-tcg-finite-rom-performance-driver";
    version = "0";
    inherit src;

    buildDeps = [pkgs.rust pkgs.coreutils pkgs.sed pkgs.python3 cargoDeps];

    phases = [
      {
        name = "assemble-public-protocol-helper";
        script = ''
          set -eu
          cp -r "$src" source
          chmod -R u+w source
          cd source
          mkdir -p performance-driver/src performance-driver/.cargo
          cp ${./tcg-managed-performance.rs} performance-driver/src/tcg-managed-performance.rs
          cp ${./tcg-finite-rom-performance.rs} performance-driver/src/main.rs
          python3 - ${./tcg-linux-serial-performance.rs} <<'PYTHON'
          import sys
          from pathlib import Path

          support = Path(sys.argv[1]).read_text().partition(
              '/// Complete common milestone, emitted before the authenticated Sim request.'
          )[0].replace('//!', '//')
          main = Path('performance-driver/src/main.rs')
          main.write_text(main.read_text() + '\n' + support)
          PYTHON
          cp crates/Cargo.lock performance-driver/Cargo.lock
          cat > performance-driver/Cargo.toml <<'MANIFEST'
          [package]
          name = "crucible-finite-rom-performance"
          version = "0.1.0"
          edition = "2024"

          [workspace]

          [dependencies]
          libc = "0.2"
          serde_json = "1"
          sha2 = "0.10"
          tempfile = "3"
          MANIFEST
          sed "s|@vendor@|${cargoDeps}|g" "${cargoDeps}/.cargo/config.toml" \
            > performance-driver/.cargo/config.toml
          cd performance-driver
        '';
      }
      {
        name = "qualify-and-build-public-protocol-helper";
        script = ''
          set -eu
          export CARGO_HOME="$TMPDIR/cargo"
          cargo test --release --offline --target-dir "$TMPDIR/target"
          cargo build --release --offline --target-dir "$TMPDIR/target"
          mkdir -p "$out/bin"
          cp "$TMPDIR/target/release/crucible-finite-rom-performance" "$out/bin/"
        '';
      }
    ];
  }
