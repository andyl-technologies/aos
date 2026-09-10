{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase5.gates.campaignStoreEquivalence",
  taskIds ? ["T-CAM-5.1" "T-CAM-5.5" "T-CAM-5.7"],
  dependencies ? [],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = import ./_cargo-deps.nix {inherit pkgs lib;};
in
  pkgs.mkDerivation {
    pname = "crucible-phase5-campaign-store-equivalence";
    version = "0";
    src = crucibleSrc;

    buildDeps =
      [
        pkgs.ca-certificates
        pkgs.coreutils
        pkgs.garage
        pkgs.gawk
        pkgs.rust
        pkgs.sed
      ]
      ++ dependencies;

    phases = [
      {
        name = "unpack";
        script = ''
          set -eu
          cp -R "$src" source
          chmod -R u+w source
          cd source
        '';
      }
      {
        name = "configure";
        script = ''
          set -eu
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
        name = "run-campaign-store-equivalence";
        script = ''
          set -eu
          if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
            cd source
          fi

          target="$TMPDIR/crucible-campaign-store-equivalence-target"
          cargo test \
            --frozen \
            --offline \
            --target-dir "$target" \
            --manifest-path crates/Cargo.toml \
            -p crucible-cas \
            --features test-support \
            --test gate_campaign_store_equivalence \
            -- --test-threads=1

          # The fake service is the deterministic emulator for multipart,
          # pagination, versioned ref CAS, failure, and cleanup semantics.
          cargo test \
            --frozen \
            --offline \
            --target-dir "$target" \
            --manifest-path crates/Cargo.toml \
            -p crucible-cas \
            --lib content_store::s3 \
            -- --test-threads=1

          garage_config="$TMPDIR/garage.toml"
          garage_root="$TMPDIR/garage"
          mkdir -p "$garage_root/meta" "$garage_root/data"
          cat > "$garage_config" <<EOF
          metadata_dir = "$garage_root/meta"
          data_dir = "$garage_root/data"
          db_engine = "sqlite"
          replication_factor = 1

          rpc_bind_addr = "127.0.0.1:3901"
          rpc_public_addr = "127.0.0.1:3901"
          rpc_secret = "1799bccfd7411eddcf9ebd316bc1f5287ad12a68094e1c6ac6abde7e6feae1ec"

          [s3_api]
          s3_region = "garage"
          api_bind_addr = "127.0.0.1:3900"
          root_domain = ".s3.garage.localhost"
          EOF

          garage -c "$garage_config" server > "$TMPDIR/garage.log" 2>&1 &
          garage_pid=$!
          cleanup() {
            if kill -0 "$garage_pid" 2>/dev/null; then
              kill "$garage_pid" 2>/dev/null || true
              wait "$garage_pid" 2>/dev/null || true
            fi
          }
          trap cleanup EXIT

          ready=false
          for attempt in $(seq 1 60); do
            if garage -c "$garage_config" status > "$TMPDIR/garage-status.out" 2>&1; then
              ready=true
              break
            fi
            sleep 1
          done
          if [ "$ready" != true ]; then
            cat "$TMPDIR/garage.log" >&2
            exit 1
          fi

          node_id=$(garage -c "$garage_config" node id -q | cut -d@ -f1)
          test -n "$node_id"
          garage -c "$garage_config" layout assign -z dc1 -c 1G "$node_id"
          garage -c "$garage_config" layout apply --version 1
          garage -c "$garage_config" key create crucible-conformance \
            > "$TMPDIR/garage-key.out"
          access_key=$(awk -F': *' '/Key ID/ {print $2}' "$TMPDIR/garage-key.out" | tr -d ' ')
          secret_key=$(awk -F': *' '/Secret key/ {print $2}' "$TMPDIR/garage-key.out" | tr -d ' ')
          test -n "$access_key"
          test -n "$secret_key"
          garage -c "$garage_config" bucket create crucible-conformance
          garage -c "$garage_config" bucket allow \
            --read --write --owner crucible-conformance \
            --key crucible-conformance

          export AWS_ACCESS_KEY_ID="$access_key"
          export AWS_SECRET_ACCESS_KEY="$secret_key"
          export AWS_REGION=garage
          export AWS_EC2_METADATA_DISABLED=true
          export SSL_CERT_FILE=${pkgs.ca-certificates}/etc/ssl/certs/ca-certificates.crt
          export CRUCIBLE_S3_TEST_ENDPOINT=http://127.0.0.1:3900
          export CRUCIBLE_S3_TEST_BUCKET=crucible-conformance
          export CRUCIBLE_S3_TEST_PREFIX=phase5-equivalence
          cargo test \
            --frozen \
            --offline \
            --target-dir "$target" \
            --manifest-path crates/Cargo.toml \
            -p crucible-s3-store \
            --test live_conformance \
            -- --ignored --test-threads=1

          cleanup
          trap - EXIT

          mkdir -p "$out"
          cat > "$out/result" <<RESULT
          PASS
          check=${attrPath}
          tasks=${builtins.concatStringsSep "," taskIds}
          gate=gate:campaign-store-equivalence
          local_leaves=memory,directory,packed
          mutable_refs=memory,directory,s3-compatible
          s3_emulator=in-process-fake-service
          s3_production_compatible_service=pkgs.garage
          s3_live_conformance=true
          RESULT
        '';
      }
    ];
  }
