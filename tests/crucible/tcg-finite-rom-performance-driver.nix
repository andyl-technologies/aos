{
  pkgs,
  lib,
}: let
  src = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = import ./_cargo-deps.nix {inherit pkgs lib;};
  controlSourceProvenance = {
    historicalHelperSha256 = "c7db55bfba0c066c52fc79fc2d08096910b74d946b5d9faafd48740176bb277a";
    reviewedHelperSha256 = "a458b498bb73a03c33c908ddd520187301779bdab1bec143245b36c47dd569b9";
    sharedSupportSha256 = "8002cc04248305b621fe9b92697642601a757237938a75c25acd71bb827fe0b6";
  };
in
  pkgs.mkDerivation {
    pname = "crucible-tcg-finite-rom-performance-driver";
    version = "0";
    inherit src;
    passthru = {inherit controlSourceProvenance;};

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
          import hashlib
          import sys
          from pathlib import Path

          frozen = Path(sys.argv[1]).read_bytes()
          if hashlib.sha256(frozen).hexdigest() != '${controlSourceProvenance.reviewedHelperSha256}':
              raise AssertionError('reviewed Linux helper changed; review control provenance explicitly')
          marker = '/// Complete common milestone, emitted before the authenticated Sim request.'
          support, separator, unused = frozen.decode().partition(marker)
          if not separator:
              raise AssertionError('public protocol support boundary missing')
          declaration = 'struct Process(Child);'
          unused, separator, shared = support.partition(declaration)
          if not separator:
              raise AssertionError('shared control support boundary missing')
          # Process, QMP, and CPU accounting remain byte-identical to the historical helper.
          if hashlib.sha256((declaration + shared).encode()).hexdigest() != '${controlSourceProvenance.sharedSupportSha256}':
              raise AssertionError('shared ordinary control support changed')
          support = support.replace('//!', '//')
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
