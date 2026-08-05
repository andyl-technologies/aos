{
  pkgs,
  lib,
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoVendor {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-fWBTuyTXJ+/0BiVbB5WAtCqVwufg04NH4BJdocT+moU=";
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
          sed "s|@vendor@|${cargoDeps}|g" "${cargoDeps}/.cargo/config.toml" \
              > .cargo/config.toml
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
