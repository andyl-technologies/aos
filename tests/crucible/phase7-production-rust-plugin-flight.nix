# Runs two diskless comparator variants and one block-recovery hot-fork subflight.
{
  pkgs,
  lib,
  attrPath,
  campaignComposition ? null,
  testing ? import ../../lib/testing {inherit pkgs lib;},
}: let
  repoRoot = ../..;
  repoRootString = toString repoRoot;
  source = builtins.path {
    path = repoRoot;
    name = "crucible-production-rust-flight-src";
    # The suite retains its complete source. This package only compiles the
    # workspace, the fixture embedded by daemon tests, and the QMP schema.
    filter = path: _type: let
      pathString = toString path;
      base = baseNameOf path;
      crates = "${repoRootString}/crates";
      licenses = "${repoRootString}/LICENSES";
    in
      base
      != ".git"
      && base != ".crucible"
      && base != "target"
      && base != "__pycache__"
      && !lib.hasSuffix ".pyc" base
      && (
        pathString
        == repoRootString
        || pathString == "${repoRootString}/LICENSE"
        || pathString == crates
        || lib.hasPrefix "${crates}/" pathString
        || pathString == licenses
        || lib.hasPrefix "${licenses}/" pathString
        || pathString == "${repoRootString}/docs"
        || pathString == "${repoRootString}/docs/rfcs"
        || pathString == "${repoRootString}/docs/rfcs/0020-crucible-campaigns"
        || pathString == "${repoRootString}/docs/rfcs/0020-crucible-campaigns/schema-registry.tsv"
        || pathString == "${repoRootString}/tests"
        || pathString == "${repoRootString}/tests/crucible"
        || pathString == "${repoRootString}/tests/crucible/fixtures"
        || pathString == "${repoRootString}/tests/crucible/fixtures/e2e-determinism.scenario.toml"
      );
  };
  cargoDeps = import ./_cargo-deps.nix {
    inherit pkgs lib;
    src = source;
  };
  guest = import ./_nginx-curl-http-200-guest.nix {inherit pkgs;};
  idleGuest = import ./phase2-qemu-live-plugin-quantum-guest.nix {inherit pkgs;};
  blockRecoveryNanos = 5000000000;
  blockGuest = import ./phase2-qemu-live-block-io-guest.nix {inherit pkgs;};
  flight = pkgs.mkDerivation {
    pname = "crucible-production-rust-plugin-flight";
    version = "0";
    LIBSQLITE3_SYS_USE_PKG_CONFIG = "1";
    src = source;
    buildDeps = [
      pkgs.coreutils
      pkgs.jq
      pkgs.openssl
      pkgs.pkg-config
      pkgs.protobuf
      pkgs.rust
      pkgs.sed

      pkgs.sqlite
    ];
    runtimeDeps = [pkgs.openssl pkgs.sqlite];

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
        name = "build";
        script = ''
          set -eu
          export CARGO_HOME="$TMPDIR/cargo"
          mkdir -p "$CARGO_HOME" .cargo
          sed "s|@vendor@|${cargoDeps}|g" \
            "${cargoDeps}/.cargo/config.toml" > .cargo/config.toml
          test "$(${pkgs.grep}/bin/grep -Fxc '        .with_console_capture()' \
            crates/crucible/control/crucible-daemon/src/packaged_qemu_executor/native_plugin_flight/driver.rs)" -eq 1
          cargo test --frozen --offline \
            --manifest-path crates/Cargo.toml \
            --target-dir "$TMPDIR/target" \
            -p crucible-daemon --features private-measurement-domain --lib \
            plugin_flight
          cargo test --frozen --offline \
            --manifest-path crates/Cargo.toml \
            --target-dir "$TMPDIR/target" \
            -p crucible-qemu-host --lib \
            spawn::tests::streamed_runtime_trace_rejects_replacement_oversize_and_partial_reads
          cargo test --frozen --offline \
            --manifest-path crates/Cargo.toml \
            --target-dir "$TMPDIR/target" \
            -p crucible-qemu-host --lib \
            runtime_trace_budget_rejects_unbounded_or_empty_admission
          cargo test --frozen --offline \
            --manifest-path crates/Cargo.toml \
            --target-dir "$TMPDIR/target" \
            -p crucible-qemu-host --lib \
            supervision::runtime_determinism_trace::tests
          cargo test --frozen --offline --release --no-run \
            --message-format=json-render-diagnostics \
            --manifest-path crates/Cargo.toml \
            --target-dir "$TMPDIR/target" \
            -p crucible-daemon --features private-measurement-domain --lib > "$TMPDIR/daemon-messages.jsonl"
          daemon_test=$(jq -r \
            'select(.reason == "compiler-artifact" and .target.name == "crucible_daemon" and .profile.test == true and .executable != null) | .executable' \
            "$TMPDIR/daemon-messages.jsonl")
          test -f "$daemon_test"
          mkdir -p "$out/bin"
          cp "$daemon_test" "$out/bin/crucible-daemon-host-parallel-flight"
          mkdir -p "$out/share"
          cp tests/crucible/fixtures/e2e-determinism.scenario.toml "$out/share/"
        '';
      }
    ];
  };
  rootImage = import ./_ram-native-root-image.nix {inherit pkgs;};
  pagingKernelSetupScript = import ./_ram-native-kernel-setup.nix {
    inherit pkgs lib rootImage;
    nativeQemu = pkgs.qemu-crucible;
    nativePlugin = pkgs.crucible-qemu-plugin;
    guest = idleGuest;
    lanes = ["plugin-four" "plugin-block" "parallel-serial" "parallel-two" "parallel-failure"];
    storageImageBytes = 17179869184;
    buildGraph = builtins.hashString "sha256" (builtins.concatStringsSep "\n" [
      pkgs.linux.drvPath
      pkgs.qemu-crucible.drvPath
      pkgs.crucible-qemu-plugin.drvPath
      flight.drvPath
      rootImage.drvPath
    ]);
  };
  rootfsDeps = [
    rootImage
    flight
    guest
    idleGuest
    blockGuest
    pkgs.qemu-crucible
    pkgs.crucible-qemu-plugin
    pkgs.linux
    pkgs.e2fsprogs
    pkgs.coreutils
    pkgs.util-linux
    pkgs.grep
    pkgs.gawk
  ];
  productionFlightCommand = ''
    ${pkgs.coreutils}/bin/timeout -k 30 1800 \
      ${flight}/bin/crucible-daemon-host-parallel-flight \
      --ignored --exact \
      packaged_qemu_executor::tests::paging_native::plugin_flight::production_managed_plugin_flight_preserves_preemption_idle_trace_and_block_recovery \
      --nocapture
  '';
  pluginAssetScript = ''
    export CRUCIBLE_PLUGIN_FLIGHT_IDLE_INITRD=${idleGuest}/initrd.img
    export CRUCIBLE_PLUGIN_FLIGHT_BLOCK_INITRD=${blockGuest}/initrd.img
    export CRUCIBLE_PLUGIN_FLIGHT_FIRMWARE=${pkgs.qemu-crucible}/share/qemu/bios-256k.bin
  '';
  inherit
    (import ./_production-plugin-flight-evidence.nix {
      inherit pkgs lib blockRecoveryNanos;
    })
    traceSummaryScript
    retainFlightResultScript
    validateFlightResultScript
    ;
  testScript = ''
    set -eu
    ${pagingKernelSetupScript}
    ${pluginAssetScript}

    result=/tmp/production-plugin-result
    flight_log=/tmp/production-managed-plugin-libtest.log
    runtime_trace=/tmp/production-reference-runtime-determinism.summary
    ${productionFlightCommand} > "$flight_log" 2>&1
    ${retainFlightResultScript}
    ${traceSummaryScript}
    ${validateFlightResultScript}
    export CRUCIBLE_HOST_PARALLEL_SCENARIO=${flight}/share/e2e-determinism.scenario.toml
    lifecycle_log=/tmp/production-lifecycle-host-parallel.log
    set +e
    ${pkgs.coreutils}/bin/timeout -k 30 3600 \
      ${flight}/bin/crucible-daemon-host-parallel-flight \
      --ignored --exact \
      qemu_campaign_lifecycle::tests::host_parallel_native::production_lifecycle_host_parallel_rounds_are_canonical_and_recoverable \
      --nocapture > "$lifecycle_log" 2>&1
    lifecycle_status=$?
    set -e
    cat "$lifecycle_log"
    if test "$lifecycle_status" -ne 0; then
      exit "$lifecycle_status"
    fi
    ${pkgs.grep}/bin/grep -Fq \
      'test result: ok. 1 passed; 0 failed; 0 ignored;' "$lifecycle_log"
    # QEMU stderr may split libtest's test-name prefix from its PASS line.
    test "$(${pkgs.grep}/bin/grep -Ec \
      '^test qemu_campaign_lifecycle::tests::host_parallel_native::production_lifecycle_host_parallel_rounds_are_canonical_and_recoverable \.\.\. ' \
      "$lifecycle_log")" -eq 1
    test_name='test qemu_campaign_lifecycle::tests::host_parallel_native::production_lifecycle_host_parallel_rounds_are_canonical_and_recoverable ... '
    if ! ${pkgs.grep}/bin/grep -Fqx "$test_name"PASS "$lifecycle_log"; then
      test "$(${pkgs.grep}/bin/grep -Fxc 'PASS' "$lifecycle_log")" -eq 1
    fi
    for evidence in \
      production_vm_lifecycle_path=true \
      production_host_parallel_requested_runs=2 \
      production_host_parallel_maximum_workers=2 \
      production_host_parallel_realized_parallelism=2 \
      production_host_parallel_commit_order=curl,io-probe \
      production_host_parallel_state_identity=true \
      production_host_parallel_time_identity=true \
      production_host_parallel_canonical_log_identity=true \
      production_host_parallel_worker_count_absent_from_checkpoint=true \
      production_host_parallel_failure_healthy_peer_advanced=true \
      production_host_parallel_failure_logical_state_uncommitted=true \
      production_host_parallel_failure_retry_poisoned=true \
      production_host_parallel_authenticated_exact_recovery=true; do
      test "$(${pkgs.grep}/bin/grep -Fxc "$evidence" "$lifecycle_log")" -eq 1
    done
    for evidence in \
      production_vm_lifecycle_path=true \
      production_host_parallel_requested_runs=2 \
      production_host_parallel_maximum_workers=2 \
      production_host_parallel_realized_parallelism=2 \
      production_host_parallel_commit_order=curl,io-probe \
      production_host_parallel_state_identity=true \
      production_host_parallel_time_identity=true \
      production_host_parallel_canonical_log_identity=true \
      production_host_parallel_worker_count_absent_from_checkpoint=true \
      production_host_parallel_failure_healthy_peer_advanced=true \
      production_host_parallel_failure_logical_state_uncommitted=true \
      production_host_parallel_failure_retry_poisoned=true \
      production_host_parallel_authenticated_exact_recovery=true; do
      ${pkgs.grep}/bin/grep -Fx "$evidence" "$lifecycle_log" >> "$result"
    done
    printf '%s\n' PRODUCTION_PLUGIN_RUNTIME_TRACE_SUMMARY_BEGIN
    ${pkgs.coreutils}/bin/base64 "$runtime_trace"
    printf '%s\n' PRODUCTION_PLUGIN_RUNTIME_TRACE_SUMMARY_END
    printf '%s\n' PRODUCTION_PLUGIN_RESULT_BEGIN
    cat "$result"
    printf '%s\n' PRODUCTION_PLUGIN_RESULT_END
    ${pkgs.util-linux}/bin/umount /var/paging-storage
    echo "check=${attrPath}"
  '';
  blockRecoveryTestScript = ''
    set -eu
    ${pagingKernelSetupScript}
    ${pluginAssetScript}

    result=/tmp/block-recovery-diagnostic-result
    flight_log=/tmp/block-recovery-managed-libtest.log
    set +e
    CRUCIBLE_PRODUCTION_PLUGIN_FLIGHT_BLOCK_RECOVERY_ONLY=1 \
      ${productionFlightCommand} > "$flight_log" 2>&1
    flight_status=$?
    set -e

    cat "$flight_log"
    if test "$flight_status" -ne 0; then
      exit "$flight_status"
    fi
    ${retainFlightResultScript}
    ${pkgs.util-linux}/bin/umount /var/paging-storage
    for evidence in \
      PASS \
      diagnostic_mode=block-recovery-only \
      block_recovery_hot_fork_subflight=true \
      block_recovery_nanos=${toString blockRecoveryNanos} \
      block_recovery_write_completed=true \
      hot_fork_template_draining=true \
      hot_fork_template_prepared=true \
      hot_fork_preparation_order=block-recovery-settled,draining,prepared; do
      test "$(${pkgs.grep}/bin/grep -Fxc "$evidence" "$result")" -eq 1
    done
    for numeric_evidence in \
      block_recovery_pause_logical_icount \
      block_recovery_pause_raw_icount \
      hot_fork_template_generation; do
      test "$(${pkgs.grep}/bin/grep -Ec "^$numeric_evidence=[1-9][0-9]*$" "$result")" -eq 1
    done
    test "$(${pkgs.grep}/bin/grep -Ec '^block_recovery_start_tick=[0-9]+$' "$result")" -eq 1
  '';
  gate = testing.mkVMTest {
    name = "crucible-production-rust-plugin-flight";
    memory = 12288;
    headlessVcpuCount = 6;
    # The complete accepted assignment and independently retained services
    # fit their authored resident and backing envelopes throughout setup.
    extraWritableMiB = 32768;
    # Two sequential plugin variants precede the separately bounded host
    # parallel subflight; the 120-second headless default cannot contain them.
    timeout = 6000;
    inherit rootfsDeps testScript;
  };
  blockRecoveryDiagnostic = testing.mkVMTest {
    name = "crucible-production-rust-plugin-block-recovery-diagnostic";
    memory = 12288;
    headlessVcpuCount = 6;
    extraWritableMiB = 32768;
    timeout = 2100;
    inherit rootfsDeps;
    testScript = blockRecoveryTestScript;
  };
  partitionDiagnostic = testing.mkVMTest {
    name = "crucible-phase4-qemu-clock-partition-diagnostic";
    memory = 12288;
    headlessVcpuCount = 6;
    extraWritableMiB = 32768;
    timeout = 2100;
    inherit rootfsDeps;
    testScript = ''
      set -eu
      ${pagingKernelSetupScript}
      ${pluginAssetScript}

      export CRUCIBLE_PHASE4_PARTITION_PROBE=1
      result=/tmp/phase4-clock-partition-result
      flight_log=/tmp/phase4-clock-partition-managed-libtest.log
      runtime_trace=/tmp/phase4-clock-partition-reference.summary
      ${productionFlightCommand} > "$flight_log" 2>&1
      ${retainFlightResultScript}
      ${traceSummaryScript}
      cat "$result"
      test -s "$runtime_trace"
      ${pkgs.grep}/bin/grep -Fxq 'PASS' "$result"
      ${pkgs.grep}/bin/grep -Fxq 'diagnostic_mode=phase4-partition-probe' "$result"
      ${pkgs.grep}/bin/grep -Fxq 'phase4_partition_span_ps=1000000' "$result"
      ${pkgs.grep}/bin/grep -Fq 'phase4_partition_exact_match=true' "$result"
      ${pkgs.util-linux}/bin/umount /var/paging-storage
    '';
  };
  exposedGate =
    gate
    // {
      inherit blockRecoveryDiagnostic partitionDiagnostic;
      passthru =
        (gate.passthru or {})
        // {
          inherit
            flight
            guest
            idleGuest
            blockGuest
            rootfsDeps
            testScript
            blockRecoveryDiagnostic
            blockRecoveryTestScript
            partitionDiagnostic
            ;
        };
    };
in
  if campaignComposition == null
  then exposedGate
  else
    import ./phase9-campaign-mode-production-rust-plugin-flight.nix {
      inherit pkgs lib testing;
      inherit (campaignComposition) mode system;
      productionGate = exposedGate;
    }
