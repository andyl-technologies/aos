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
          python3 - ${./tcg-linux-serial-performance.rs} ${./tcg-finite-rom-performance.rs} <<'PYTHON'
          import hashlib
          import sys
          from pathlib import Path

          frozen = Path(sys.argv[1]).read_bytes()
          expected = '675114b2441a71a473d78b070407c6f84e84ab5d29fd297b350549de280f377b'
          if hashlib.sha256(frozen).hexdigest() != expected:
              raise AssertionError('frozen Linux helper changed; review shared support explicitly')
          marker = '/// Complete common milestone, emitted before the authenticated Sim request.'
          support, separator, unused = frozen.decode().partition(marker)
          if not separator:
              raise AssertionError('public protocol support boundary missing')
          support = support.replace('//!', '//')
          driver = Path(sys.argv[2]).read_text()
          Path('performance-driver/src/main.rs').write_text(driver + '\n' + support)
          PYTHON
          cp crates/Cargo.lock performance-driver/Cargo.lock
          cat > performance-driver/Cargo.toml <<'MANIFEST'
          [package]
          name = "crucible-finite-rom-performance"
          version = "0.1.0"
          edition = "2024"

          [workspace]

          [dependencies]
          crucible-protocol = { path = "../crates/crucible-protocol" }
          crucible-shmem = { path = "../crates/crucible-shmem" }
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
