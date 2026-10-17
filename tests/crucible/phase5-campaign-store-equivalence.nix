{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase5.gates.campaignStoreEquivalence",
  taskIds ? ["T-CAM-5.1" "T-CAM-5.5" "T-CAM-5.7" "T-CAM-5.8"],
  dependencies ? [],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = import ./_cargo-deps.nix {inherit pkgs lib;};

  nativeGcIntegration = import ./phase5-cli-native-gc-integration.nix {inherit pkgs lib;};
  nativeQemu = pkgs.qemu-crucible;
  nativePlugin = pkgs.crucible-qemu-plugin;
  rootImage = import ./_ram-native-root-image.nix {inherit pkgs;};
  guest = import ./phase4-packaged-campaign-choice-guest.nix {inherit pkgs;};
  quotaInstaller = import ./_catalog-quota-installer.nix {inherit pkgs lib;};
  gateway = pkgs.crucible.passthru.debugGateway;
  inherit (nativeGcIntegration.passthru) flight deployment sourcePolicy;
  liveS3Executions = [
    {
      selector = "live_s3_product::public_worked_network_survives_live_s3_outage_and_credential_expiry";
      marker = "live_s3_worked_network_outage_credentials_gc=true";
    }
    {
      selector = "live_s3_product::public_paused_composed_campaign_survives_s3_outage_repack_archive_and_gc";
      marker = "composed_s3_packed_pause_outage_repack_archive_gc=true";
    }
  ];
  # The same source-built server and TLS startup serves neutral host conformance
  # and the campaign product tests inside the installed-quota kernel profile.
  garageSetup = ''
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

  '';
  garageTlsSetup = ''
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

  '';
  liveS3BuildGraph = builtins.hashString "sha256" (lib.concatStringsSep "\n" ([
      pkgs.linux.drvPath
      nativeQemu.drvPath
      nativePlugin.drvPath
      rootImage.drvPath
      flight.drvPath
      guest.drvPath
      quotaInstaller.drvPath
      gateway.drvPath
      pkgs.garage.drvPath
      pkgs.openssl.drvPath
      pkgs.socat.drvPath
      (toString deployment)
      (toString sourcePolicy)
      garageSetup
      garageTlsSetup
    ]
    ++ map (execution: "campaign_store_process:${execution.selector}:${execution.marker}") liveS3Executions));
  setup = import ./_ram-native-kernel-setup.nix {
    inherit pkgs lib nativeQemu nativePlugin guest rootImage;
    lanes = ["live-s3-0" "live-s3-1"];
    buildGraph = liveS3BuildGraph;
    storageImageBytes = 34359738368;
  };
  runLiveS3Execution = index: execution: ''
    storage="/var/paging-storage/live-s3-${toString index}"
    cgroup="/sys/fs/cgroup/paging/live-s3-${toString index}"
    first_project=${toString (66000 + index * 100)}
    catalog_project=${toString (66200 + index)}
    registry_project=${toString (66300 + index)}
    store_project=${toString (66400 + index)}
    mkdir -m 700 "$storage/run" "$storage/run-state"
    ${quotaInstaller}/bin/install-catalog-quota \
      "$storage" "$storage/scratch" "$store_project" 2147483648 1048576
    ${quotaInstaller}/bin/install-catalog-quota \
      "$storage" "$storage/ram-catalogs" "$catalog_project" 2147483648 262144
    ${quotaInstaller}/bin/install-catalog-quota \
      "$storage" "$storage/executor-ledger" "$registry_project" 16777216 65536
    export TMPDIR="$storage/scratch"
    export CRUCIBLE_FLIGHT_STORE_PROJECT="$store_project"
    ${pkgs.sed}/bin/sed -e "s|@SCRATCH@|$TMPDIR|g" \
      -e "s|@STORE_PROJECT@|$store_project|g" ${sourcePolicy} > "$storage/source-policy.toml"
    chmod 600 "$storage/source-policy.toml"
    export CRUCIBLE_FLIGHT_SOURCE_POLICY="$storage/source-policy.toml"
    ${pkgs.sed}/bin/sed \
      -e "s|@CGROUP@|$cgroup|g" -e "s|@STORAGE@|$storage|g" \
      -e "s|@FIRST_PROJECT@|$first_project|g" \
      -e "s|@CATALOG_PROJECT@|$catalog_project|g" \
      -e "s|@REGISTRY_PROJECT@|$registry_project|g" \
      ${deployment} > "$storage/executor.toml"
    chmod 600 "$storage/executor.toml"
    export CRUCIBLE_FLIGHT_DEPLOYMENT="$storage/executor.toml"
    export CRUCIBLE_CAMPAIGN_DEPLOYMENT="$storage/executor.toml"
    export CRUCIBLE_FLIGHT_RUN_ROOT="$storage/run"
    export CRUCIBLE_RUN_STATE_ROOT="$storage/run-state"
    ${garageSetup}
    ${garageTlsSetup}
    log="/tmp/live-s3-${toString index}.log"
    ${flight}/bin/campaign_store_process --list --ignored > "$log.list"
    test "$(${pkgs.grep}/bin/grep -Fxc '${execution.selector}: test' "$log.list")" -eq 1
    set +e
    ${pkgs.coreutils}/bin/timeout -k 30 2700 \
      ${flight}/bin/campaign_store_process --exact '${execution.selector}' \
      --ignored --nocapture --test-threads=1 > "$log" 2>&1
    status=$?
    set -e
    cat "$log"
    test "$status" -eq 0
    ${pkgs.grep}/bin/grep -Fq '${execution.marker}' "$log"
    ${pkgs.grep}/bin/grep -Fq 'test result: ok. 1 passed; 0 failed; 0 ignored;' "$log"
    cleanup
    trap - EXIT
    echo 'live_s3_native_selector_pass=campaign_store_process:${execution.selector}'
  '';
  liveS3Rootfs = (import ../../lib/testing/firecracker.nix {inherit pkgs lib;}).mkFirecrackerRootfs {
    pname = "crucible-live-s3-campaign-integration";
    extraWritableMiB = 36864;
    rootfsDeps = [flight deployment sourcePolicy guest rootImage quotaInstaller gateway nativeQemu nativePlugin pkgs.crucible pkgs.linux pkgs.coreutils pkgs.grep pkgs.sed pkgs.e2fsprogs pkgs.util-linux pkgs.garage pkgs.gawk pkgs.openssl pkgs.socat pkgs.ca-certificates pkgs.iproute2];
    testScript = ''
      set -eu
      ${setup}
      ${pkgs.iproute2}/bin/ip link set lo up
      export CRUCIBLE_PROCESS_FLIGHT_BINARY=${flight}/bin/crucible
      export CRUCIBLE_EXACT_BUNDLE_BINARY=${flight}/bin/crucible
      export CRUCIBLE_FLIGHT_QEMU="$CRUCIBLE_PAGING_QEMU"
      export CRUCIBLE_FLIGHT_PLUGIN="$CRUCIBLE_PAGING_PLUGIN"
      export CRUCIBLE_DEBUG_GATEWAY=${gateway}/bin/crucible-debug-gateway
      export CRUCIBLE_KERNEL="$CRUCIBLE_PAGING_KERNEL"
      export CRUCIBLE_INITRD=${guest}/initrd.img
      export CRUCIBLE_ROOT_IMAGE=${flight}/root.raw
      export CRUCIBLE_NATIVE_GUEST_ARCHITECTURE=x86_64
      ${lib.concatStringsSep "\n" (builtins.genList (index: runLiveS3Execution index (builtins.elemAt liveS3Executions index)) (builtins.length liveS3Executions))}
      ${pkgs.util-linux}/bin/umount /var/paging-storage
      echo live_s3_native_executions=2
      echo live_s3_native_build_graph=${liveS3BuildGraph}
    '';
  };
  liveS3Native = pkgs.mkDerivation {
    pname = "crucible-live-s3-campaign-integration";
    version = "0";
    src = null;
    requiredSystemFeatures = ["kvm"];
    buildDeps = [pkgs.coreutils pkgs.grep pkgs.qemu];
    phases = [
      {
        name = "run-live-s3-campaign-integration";
        script = ''
          set -eu
          mkdir -p "$out"
          cp ${liveS3Rootfs} rootfs.img
          chmod u+w rootfs.img
          for kernel in ${pkgs.linux}/boot/vmlinuz-*; do kernel_image="$kernel"; done
          set +e
          ${pkgs.coreutils}/bin/timeout -k 30 7200 \
            ${pkgs.qemu}/bin/qemu-system-x86_64 \
            -machine q35,accel=tcg -cpu max -smp 11 -m 8192 \
            -nodefaults -display none -serial stdio -monitor none -no-reboot \
            -kernel "$kernel_image" \
            -append 'console=ttyS0 reboot=k panic=1 root=/dev/vda rw init=/init net.ifnames=0' \
            -drive file=rootfs.img,format=raw,if=virtio > "$out/serial.raw.log" 2>&1
          status=$?
          set -e
          ${pkgs.coreutils}/bin/tr -d '\r' < "$out/serial.raw.log" > "$out/serial.log"
          cat "$out/serial.log"
          test "$status" -eq 0
          ${pkgs.grep}/bin/grep -Fxq TEST_RESULT:PASS "$out/serial.log"
          test "$(${pkgs.grep}/bin/grep -Fc live_s3_native_selector_pass= "$out/serial.log")" -eq 2
          ${pkgs.grep}/bin/grep -Fxq live_s3_native_executions=2 "$out/serial.log"
          ${pkgs.grep}/bin/grep -Fxq live_s3_native_build_graph=${liveS3BuildGraph} "$out/serial.log"
          {
            echo PASS
            ${pkgs.grep}/bin/grep '^live_s3_native_' "$out/serial.log"
          } > "$out/result"
        '';
      }
    ];
  };
in
  pkgs.mkDerivation {
    pname = "crucible-phase5-campaign-store-equivalence";
    version = "0";
    LIBSQLITE3_SYS_USE_PKG_CONFIG = "1";
    runtimeDeps = [pkgs.sqlite];
    src = crucibleSrc;
    passthru = {inherit liveS3Native liveS3Rootfs liveS3BuildGraph nativeGcIntegration;};

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

        pkgs.pkg-config
        pkgs.sqlite
        nativeGcIntegration
        liveS3Native
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

          packed_test=archive_transfer::public_worked_network_archive_survives_packed_repack_outage_and_corruption
          native_gc_result=${nativeGcIntegration}/result
          test "$(grep -Fxc PASS "$native_gc_result")" -eq 1
          grep -Fxq gate=gate:cli-native-gc-integration "$native_gc_result"
          grep -Fxq cli_native_gc_executions=14 "$native_gc_result"
          grep -Fxq cli_native_gc_build_graph=${nativeGcIntegration.passthru.buildGraph} "$native_gc_result"
          packed_receipt="cli_native_gc_selector_pass=campaign_store_process:$packed_test"
          test "$(grep -Fxc "$packed_receipt" "$native_gc_result")" -eq 1
          test "$(grep -Fxc "$packed_receipt" ${nativeGcIntegration}/serial.log)" -eq 1
          cp ${nativeGcIntegration}/serial.log "$TMPDIR/packed-worked-network.log"
          grep -Fq 'packed_worked_network_archive_repack_outage_corruption_gc=true' "$TMPDIR/packed-worked-network.log"
          grep -Fq 'archive_transfer_imported_campaign_authenticated=true' "$TMPDIR/packed-worked-network.log"

          ${garageSetup}

          cargo test \
            --frozen \
            --offline \
            --target-dir "$target" \
            --manifest-path crates/Cargo.toml \
            -p crucible-s3-store \
            --test live_conformance \
            -- --ignored --test-threads=1

          ${garageTlsSetup}

          native_s3_result=${liveS3Native}/result
          test "$(grep -Fxc PASS "$native_s3_result")" -eq 1
          grep -Fxq live_s3_native_executions=2 "$native_s3_result"
          grep -Fxq live_s3_native_build_graph=${liveS3BuildGraph} "$native_s3_result"
          ${lib.concatMapStringsSep "\n" (execution: ''
              test "$(grep -Fxc 'live_s3_native_selector_pass=campaign_store_process:${execution.selector}' "$native_s3_result")" -eq 1
              test "$(grep -Fxc 'live_s3_native_selector_pass=campaign_store_process:${execution.selector}' ${liveS3Native}/serial.log)" -eq 1
              grep -Fq '${execution.marker}' ${liveS3Native}/serial.log
            '')
            liveS3Executions}
          cp ${liveS3Native}/serial.log "$TMPDIR/live-s3-product.log"
          cp ${liveS3Native}/serial.log "$TMPDIR/live-s3-composed.log"

          cleanup
          trap - EXIT

          mkdir -p "$out/evidence"
          cp "$TMPDIR/packed-worked-network.log" "$out/evidence/packed-worked-network.log"
          cp "$TMPDIR/live-s3-product.log" "$out/evidence/live-s3-product.log"
          cp "$TMPDIR/live-s3-composed.log" "$out/evidence/live-s3-composed.log"
          packed_sha256=$(sha256sum "$out/evidence/packed-worked-network.log" | cut -d ' ' -f 1)
          product_sha256=$(sha256sum "$out/evidence/live-s3-product.log" | cut -d ' ' -f 1)
          composed_sha256=$(sha256sum "$out/evidence/live-s3-composed.log" | cut -d ' ' -f 1)
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
          composed_s3_packed_pause_outage_repack_archive_gc=true
          composed_s3_packed_evidence_sha256=$composed_sha256
          packed_worked_network_archive_repack_outage_corruption_gc=true
          packed_worked_network_imported_campaign_retained=true
          packed_worked_network_evidence_sha256=$packed_sha256
          packed_worked_network_native_build_graph=${nativeGcIntegration.passthru.buildGraph}
          live_s3_native_build_graph=${liveS3BuildGraph}
          live_s3_native_executions=2
          RESULT
        '';
      }
    ];
  }
