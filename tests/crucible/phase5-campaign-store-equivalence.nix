{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase5.gates.campaignStoreEquivalence",
  taskIds ? ["T-CAM-5.1" "T-CAM-5.5" "T-CAM-5.7" "T-CAM-5.8"],
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
        pkgs.grep
        pkgs.openssl
        pkgs.rust
        pkgs.sed
        pkgs.socat
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
          s3_listing=$(cargo test \
            --frozen \
            --offline \
            --target-dir "$target" \
            --manifest-path crates/Cargo.toml \
            -p crucible-cas \
            --lib content_store::s3 \
            -- --list)
          for expected_test in \
            content_store::s3::tests::behavior::s3_blob_leaf_passes_the_shared_persistent_conformance_suite \
            content_store::s3_ref::tests::s3_ref_leaf_passes_the_shared_persistent_conformance_suite
          do
            printf '%s\n' "$s3_listing" | grep -Fqx "$expected_test: test"
          done
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
          tls_pid=
          cleanup() {
            if [ -n "$tls_pid" ] && kill -0 "$tls_pid" 2>/dev/null; then
              kill "$tls_pid" 2>/dev/null || true
              wait "$tls_pid" 2>/dev/null || true
            fi
            if kill -0 "$garage_pid" 2>/dev/null; then
              kill -CONT "$garage_pid" 2>/dev/null || true
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

          openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
            -keyout "$TMPDIR/garage-ca.key" -out "$TMPDIR/garage-ca.crt" \
            -subj /CN=Garage-local-test-CA \
            -addext 'basicConstraints=critical,CA:TRUE' \
            > "$TMPDIR/garage-tls-create.log" 2>&1
          openssl req -newkey rsa:2048 -nodes \
            -keyout "$TMPDIR/garage-tls.key" -out "$TMPDIR/garage-tls.csr" \
            -subj /CN=localhost >> "$TMPDIR/garage-tls-create.log" 2>&1
          printf '%s\n' \
            'basicConstraints=critical,CA:FALSE' \
            'subjectAltName=IP:127.0.0.1' \
            'extendedKeyUsage=serverAuth' > "$TMPDIR/garage-tls.ext"
          openssl x509 -req -in "$TMPDIR/garage-tls.csr" \
            -CA "$TMPDIR/garage-ca.crt" -CAkey "$TMPDIR/garage-ca.key" \
            -CAcreateserial -days 1 -extfile "$TMPDIR/garage-tls.ext" \
            -out "$TMPDIR/garage-tls.crt" \
            >> "$TMPDIR/garage-tls-create.log" 2>&1
          cat "$TMPDIR/garage-tls.key" "$TMPDIR/garage-tls.crt" \
            > "$TMPDIR/garage-tls.pem"
          socat \
            "OPENSSL-LISTEN:3902,reuseaddr,fork,cert=$TMPDIR/garage-tls.pem,verify=0" \
            TCP:127.0.0.1:3900 > "$TMPDIR/garage-tls.log" 2>&1 &
          tls_pid=$!
          tls_ready=false
          for attempt in $(seq 1 30); do
            if openssl s_client -connect 127.0.0.1:3902 \
              -verify_ip 127.0.0.1 \
              -CAfile "$TMPDIR/garage-ca.crt" -verify_return_error \
              < /dev/null > "$TMPDIR/garage-tls-verify.log" 2>&1; then
              tls_ready=true
              break
            fi
            sleep 1
          done
          if [ "$tls_ready" != true ]; then
            cat "$TMPDIR/garage-tls.log" >&2
            exit 1
          fi
          grep -Fq 'Verify return code: 0 (ok)' "$TMPDIR/garage-tls-verify.log"

          export SSL_CERT_FILE="$TMPDIR/garage-ca.crt"
          export CRUCIBLE_S3_TEST_UNTRUSTED_CA=${pkgs.ca-certificates}/etc/ssl/certs/ca-certificates.crt
          export CRUCIBLE_S3_TEST_ENDPOINT=https://127.0.0.1:3902
          export CRUCIBLE_S3_TEST_GARAGE_PID="$garage_pid"
          export CRUCIBLE_S3_TEST_KILL=${pkgs.coreutils}/bin/kill
          if ! cargo test \
            --frozen \
            --offline \
            --target-dir "$target" \
            --manifest-path crates/Cargo.toml \
            -p crucible-cli \
            --test campaign_store_process \
            live_s3_product::public_worked_network_survives_live_s3_outage_and_credential_expiry \
            -- --ignored --exact --nocapture --test-threads=1 \
            > "$TMPDIR/live-s3-product.log" 2>&1; then
            cat "$TMPDIR/live-s3-product.log" >&2
            exit 1
          fi
          grep -Fq 'live_s3_worked_network_outage_credentials_gc=true' \
            "$TMPDIR/live-s3-product.log"
          grep -Fq 'test result: ok. 1 passed; 0 failed; 0 ignored;' \
            "$TMPDIR/live-s3-product.log"

          cleanup
          trap - EXIT

          mkdir -p "$out/evidence"
          cp "$TMPDIR/live-s3-product.log" "$out/evidence/live-s3-product.log"
          product_sha256=$(sha256sum "$out/evidence/live-s3-product.log" | cut -d ' ' -f 1)
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
          s3_live_worked_network_outage_credential_recovery=true
          s3_live_product_evidence_sha256=$product_sha256
          RESULT
        '';
      }
    ];
  }
