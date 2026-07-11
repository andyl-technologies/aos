{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase2.qemuLiveGenesisExecutor",
  taskIds ? ["T-QEMU-16"],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoDeps {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-6Ig56XHLaW8Ow70BXh/oVSblxDoU4dkK5XqZJmd2RUw=";
  };
  s11GuestCheck = import ./phase0-s11.nix {
    inherit pkgs lib;
    stopAt = 1;
  };
  s11Guest = s11GuestCheck.passthru.crucibleSmpGuest;

  # Exact bytes produced by GuestEntropySeed::from_scenario_seed(0x0010_c001).
  guestSeed = pkgs.mkDerivation {
    pname = "crucible-live-genesis-seed";
    version = "0";
    src = null;
    phases = [
      {
        name = "materialize-seed";
        script = ''
          set -eu
          mkdir -p "$out"
          printf '\070\130\271\071\150\151\146\007\322\313\013\266\024\253\256\032\114\205\011\004\350\142\140\177\061\235\337\203\174\344\353\345' \
            > "$out/seed.bin"
          test "$(wc -c < "$out/seed.bin")" -eq 32
        '';
      }
    ];
  };

  exampleSource = builtins.readFile ../../crates/crucible-qemu/examples/crucible-qemu-live-genesis.rs;
  executorSource = builtins.readFile ../../crates/crucible-qemu/src/single_vm_fingerprint/live_runner/genesis_probe.rs;
  defaultChecks = builtins.readFile ./default.nix;

  hasInfix = needle: haystack: let
    needleLen = builtins.stringLength needle;
    haystackLen = builtins.stringLength haystack;
    maxStart = haystackLen - needleLen;
    indexes =
      if needleLen == 0
      then [0]
      else if maxStart < 0
      then []
      else builtins.genList (index: index) (maxStart + 1);
  in
    builtins.any (index:
      builtins.substring index needleLen haystack == needle)
    indexes;

  required = [
    {
      label = "public live definition-preflight execution";
      content = exampleSource;
      needle = "LiveDefinitionPreflightEvidence::execute";
    }
    {
      label = "public production genesis report execution";
      content = exampleSource;
      needle = "probe_genesis_report";
    }
    {
      label = "typed production Unix QMP connector";
      content = exampleSource;
      needle = "TypedLiveRunnerQmpConnector";
    }
    {
      label = "actual completed-attempt evidence";
      content = executorSource;
      needle = "pub struct LiveGenesisProbeReport";
    }
    {
      label = "phase2 check exposure";
      content = defaultChecks;
      needle = "qemuLiveGenesisExecutor = import ./phase2-qemu-live-genesis-executor.nix";
    }
  ];
  failures =
    lib.concatMap (
      requirement:
        lib.optionals (!(hasInfix requirement.needle requirement.content)) [
          "missing ${requirement.label}: `${requirement.needle}`"
        ]
    )
    required;
in
  if failures != []
  then throw "crucible phase2 live genesis executor check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase2-qemu-live-genesis-executor";
      version = "0";
      src = crucibleSrc;

      buildDeps = [
        pkgs.coreutils
        pkgs.grep
        pkgs.qemu-crucible
        pkgs.crucible-qemu-trace-plugin
        pkgs.rust
        pkgs.sed
      ];

      GUEST_FIRMWARE = "${pkgs.qemu-crucible}/share/qemu/bios-256k.bin";
      GUEST_INITRD = "${s11Guest.initramfs}/initrd.img";
      GUEST_KERNEL = builtins.toString s11Guest.kernel;
      GUEST_KERNEL_APPEND = s11Guest.stockEntropyKernelAppend;
      GUEST_SEED = "${guestSeed}/seed.bin";
      QEMU_BINARY = "${pkgs.qemu-crucible}/bin/qemu-system-x86_64";
      TRACE_PLUGIN = "${pkgs.crucible-qemu-trace-plugin}/lib/qemu/plugins/crucible-qemu-trace-plugin.so";
      TASK_IDS = builtins.concatStringsSep "," taskIds;
      ATTR_PATH = attrPath;

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
          name = "run-live-genesis-executor";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            vmlinuz=$(ls "$GUEST_KERNEL"/boot/vmlinuz-* | head -1)
            test -n "$vmlinuz"

            cargo build \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/live-genesis-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible-qemu \
              --example crucible-qemu-live-genesis

            artifact_root="$TMPDIR/live-genesis"
            report="$TMPDIR/live-genesis.result"
            "$TMPDIR/live-genesis-target/debug/examples/crucible-qemu-live-genesis" \
              "$QEMU_BINARY" \
              "$GUEST_FIRMWARE" \
              "$vmlinuz" \
              "$GUEST_INITRD" \
              "$GUEST_SEED" \
              "$TRACE_PLUGIN" \
              "$artifact_root" \
              "$GUEST_KERNEL_APPEND" \
              > "$report"

            grep -Fxq PASS "$report"
            grep -Fxq 'preflight_qmp_state=prelaunch' "$report"
            grep -Fxq 'preflight_qmp_running=false' "$report"
            grep -Fxq 'preflight_shutdown=natural-success' "$report"
            grep -Fxq 'genesis_first_qmp_state=prelaunch' "$report"
            grep -Fxq 'genesis_second_qmp_state=prelaunch' "$report"
            grep -Fxq 'genesis_first_qmp_running=false' "$report"
            grep -Fxq 'genesis_second_qmp_running=false' "$report"
            grep -Fxq 'genesis_first_shutdown=natural-success' "$report"
            grep -Fxq 'genesis_second_shutdown=natural-success' "$report"
            grep -Fxq 'genesis_fingerprints_equal=true' "$report"
            grep -Fxq 'fresh_attempt_directories_distinct=true' "$report"
            grep -Fxq 'fresh_control_identities_distinct=true' "$report"
            grep -Fxq 'fresh_invocation_identities_distinct=true' "$report"
            grep -Fxq 'fresh_raw_argv_identities_distinct=true' "$report"
            grep -Fxq 'negative_nonzero_target_rejected=true' "$report"
            grep -Fxq 'negative_scenario_drift_rejected=true' "$report"
            grep -Fxq 'no_failed_request_attempt_allocated=true' "$report"

            test -s "$artifact_root/preflight/attempt-00000001/preflight.jsonl"
            test -s "$artifact_root/probes/attempt-00000001/trace.jsonl"
            test -s "$artifact_root/probes/attempt-00000002/trace.jsonl"
            test ! -e "$artifact_root/probes/attempt-00000003"

            mkdir -p "$out"
            cp "$report" "$out/result"
            {
              printf 'attr_path=%s\n' "$ATTR_PATH"
              printf 'task_ids=%s\n' "$TASK_IDS"
              printf 'guest_artifacts=actual-immutable-store-inputs\n'
              printf 'qmp_connector=typed-unix-production\n'
              printf 'process_owner=live-observation-process\n'
            } >> "$out/result"
          '';
        }
      ];
    }
