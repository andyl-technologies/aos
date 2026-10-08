{
  pkgs,
  lib,
}: let
  src = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = import ./_cargo-deps.nix {inherit pkgs lib;};
in
  pkgs.mkDerivation {
    pname = "crucible-tcg-linux-serial-performance-driver";
    version = "0";
    inherit src;

    buildDeps = [pkgs.rust pkgs.coreutils pkgs.sed cargoDeps];

    phases = [
      {
        name = "prepare-public-protocol-fixture";
        script = ''
          set -eu
          cp -r "$src" source
          chmod -R u+w source
          cd source
          mkdir -p performance-driver/src performance-driver/.cargo
          cp ${./tcg-linux-serial-performance.rs} performance-driver/src/main.rs
          cp crates/Cargo.lock performance-driver/Cargo.lock

          cat > performance-driver/Cargo.toml <<'MANIFEST'
          [package]
          name = "crucible-linux-serial-performance"
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
        name = "build-public-protocol-fixture";
        script = ''
          set -eu
          export CARGO_HOME="$TMPDIR/cargo"
          cargo test --release --offline --target-dir "$TMPDIR/target"
          cargo build --release --offline --target-dir "$TMPDIR/target"
          mkdir -p "$out/bin"
          cp "$TMPDIR/target/release/crucible-linux-serial-performance" "$out/bin/"
        '';
      }
    ];
  }
