{
  pkgs,
  lib,
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoDeps {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-ULD9g6d87886b8O6/sGCMktquGwaUAyf+DLHUrFzod0=";
  };
in
  pkgs.mkDerivation {
    pname = "crucible-live-io-runner";
    version = "0";
    src = crucibleSrc;

    buildDeps = [
      pkgs.coreutils
      pkgs.rust
      pkgs.sed
    ];

    phases = [
      {
        name = "unpack";
        script = ''
          cp -R "$src" source
          chmod -R u+w source
          cd source
        '';
      }
      {
        name = "configure";
        script = ''
          export CARGO_HOME="$TMPDIR/cargo"
          if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
            cd source
          fi
          mkdir -p "$CARGO_HOME" .cargo
          if [ -f "${cargoDeps}/.cargo/config.toml" ]; then
            sed "s|@vendor@|${cargoDeps}|g" "${cargoDeps}/.cargo/config.toml" \
              > .cargo/config.toml
          else
            printf '[source.crates-io]\nreplace-with = "vendored-sources"\n\n[source.vendored-sources]\ndirectory = "${cargoDeps}"\n\n' \
              > .cargo/config.toml
          fi
        '';
      }
      {
        name = "build";
        script = ''
          if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
            cd source
          fi
          cargo build \
            --frozen \
            --offline \
            --target-dir "$TMPDIR/live-io-target" \
            --manifest-path crates/Cargo.toml \
            -p crucible-qemu \
            --example crucible-qemu-live-block-io \
            --example crucible-qemu-live-ninep-io
        '';
      }
      {
        name = "install";
        script = ''
          mkdir -p "$out/bin"
          cp \
            "$TMPDIR/live-io-target/debug/examples/crucible-qemu-live-block-io" \
            "$TMPDIR/live-io-target/debug/examples/crucible-qemu-live-ninep-io" \
            "$out/bin/"
        '';
      }
    ];
  }
