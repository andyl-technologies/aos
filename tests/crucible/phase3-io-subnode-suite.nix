{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase3.ioSubnodeSuite",
  taskIds ? [],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoDeps {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-ULD9g6d87886b8O6/sGCMktquGwaUAyf+DLHUrFzod0=";
  };
  taskList = builtins.concatStringsSep "," taskIds;
in
  pkgs.mkDerivation {
    pname = "crucible-phase3-io-subnode-suite";
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
        name = "run-io-subnode-suite";
        script = ''
          set -eu
          if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
            cd source
          fi
          cargo test \
            --frozen \
            --offline \
            --target-dir "$TMPDIR/crucible-io-subnode-suite-target" \
            --manifest-path crates/Cargo.toml \
            -p crucible-device \
            -- --test-threads=1
          cargo test \
            --frozen \
            --offline \
            --target-dir "$TMPDIR/crucible-io-subnode-suite-target" \
            --manifest-path crates/Cargo.toml \
            -p crucible \
            --lib \
            device \
            -- --test-threads=1
        '';
      }
      {
        name = "write-result";
        script = ''
          set -eu
          mkdir -p "$out"
          cat > "$out/result" <<'RESULT'
          PASS
          check=${attrPath}
          tasks=${taskList}
          component=crucible-device
          io_subnode_trait=true
          block_overlay=true
          block_completion_model=true
          block_snapshot_restore=true
          ninep_server=true
          ninep_session_lifecycle=true
          ninep_wire_abi=true
          network_link_subnode=true
          RESULT
        '';
      }
    ];
  }
