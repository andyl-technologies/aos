{
  pkgs,
  lib,
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = import ./_cargo-deps.nix {inherit pkgs lib;};
in
  pkgs.mkDerivation {
    pname = "crucible-live-io-runner";
    version = "0";
    src = crucibleSrc;

    buildDeps = [
      pkgs.coreutils
      pkgs.grep
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

          # The live 9p binary depends on an event-driven device cursor: an
          # empty host poll must not outrun a request whose active flag becomes
          # visible just before its ring publication. List the exact regression
          # first so removing or renaming it cannot turn Cargo's zero-test
          # success into certifying evidence.
          test_name='supervision::ninep_io_servicer::tests::empty_poll_cannot_advance_past_later_request_completion'
          cargo test \
            --frozen \
            --offline \
            --target-dir "$TMPDIR/live-io-target" \
            --manifest-path crates/Cargo.toml \
            -p crucible-qemu \
            --lib \
            -- \
            --list > "$TMPDIR/live-io-tests"
          grep -Fxq "$test_name: test" "$TMPDIR/live-io-tests"
          cargo test \
            --frozen \
            --offline \
            --target-dir "$TMPDIR/live-io-target" \
            --manifest-path crates/Cargo.toml \
            -p crucible-qemu \
            --lib \
            "$test_name" \
            -- \
            --exact
          printf 'empty_poll_request_publication_race=passed\n' \
            > "$TMPDIR/live-io-regressions"
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
          cp "$TMPDIR/live-io-regressions" "$out/regressions"
        '';
      }
    ];
  }
