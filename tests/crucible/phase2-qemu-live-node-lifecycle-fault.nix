{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase2.qemuLiveNodeLifecycleFault",
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = import ./_cargo-deps.nix {inherit pkgs lib;};
  fullSeries = import ../../pkgs/emulation/qemu-patches/_series.nix;
  patchesWithoutTypedResult = lib.init fullSeries.patches;
  lastPrefixPatch = builtins.elemAt patchesWithoutTypedResult (builtins.length patchesWithoutTypedResult - 1);
  seriesWithoutTypedResult =
    fullSeries
    // {
      patches = patchesWithoutTypedResult;
      patchFiles = map (patch: patch.file) patchesWithoutTypedResult;
      patchBranchHeadCommit = lastPrefixPatch.branchCommit;
    };
  qemuWithoutTypedResult = pkgs.qemuCrucibleNonDistributableTestPrefix {
    pname = "qemu-crucible-without-typed-node-result";
    series = seriesWithoutTypedResult;
  };
  pluginWithoutTypedResult = pkgs.crucibleQemuPluginFor qemuWithoutTypedResult;
in
  pkgs.mkDerivation {
    pname = "crucible-phase2-qemu-live-node-lifecycle-fault";
    version = "0";
    src = crucibleSrc;

    buildDeps = [
      pkgs.coreutils
      pkgs.crucible-qemu-plugin
      pkgs.grep
      pkgs.qemu-crucible
      qemuWithoutTypedResult
      pkgs.rust
      pkgs.sed
      pluginWithoutTypedResult
    ];

    GUEST_KERNEL = builtins.toString pkgs.linux;
    GUEST_FIRMWARE = "${pkgs.qemu-crucible}/share/qemu/bios-256k.bin";
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
          sed "s|@vendor@|${cargoDeps}|g" "${cargoDeps}/.cargo/config.toml" \
            > .cargo/config.toml
        '';
      }
      {
        name = "run-live-node-lifecycle-fault";
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
            --target-dir "$TMPDIR/live-node-lifecycle-target" \
            --manifest-path crates/Cargo.toml \
            -p crucible-qemu \
            --example crucible-qemu-live-node-lifecycle-fault

          run_dir="$TMPDIR/live-node-lifecycle-run"
          mkdir -p "$run_dir"
          report="$TMPDIR/live-node-lifecycle.result"
          timeout -k 15 590 \
            "$TMPDIR/live-node-lifecycle-target/debug/examples/crucible-qemu-live-node-lifecycle-fault" \
            ${pkgs.qemu-crucible}/bin/qemu-system-x86_64 \
            ${pkgs.crucible-qemu-plugin}/lib/libcrucible_qemu_plugin.so \
            "$vmlinuz" \
            "$GUEST_FIRMWARE" \
            "$run_dir" \
            > "$report"

          cat "$report"
          grep -Fxq PASS "$report"
          grep -Fxq 'gate=gate:live-node-lifecycle-fault' "$report"
          grep -Fxq 'exact_manifest_replay_admitted=true' "$report"
          grep -Fxq 'changed_state_precondition_rejected=true' "$report"
          grep -Fxq 'corrupt_result_rejected_with_valid_event=true' "$report"
          grep -Fxq 'corrupt_event_rejected_with_valid_result=true' "$report"
          grep -Fxq 'cross_adapter_actions_committed=true' "$report"
          grep -Fxq 'cross_adapter_rejection_rolled_back=true' "$report"
          grep -Fxq 'backend=production-qemu-signal-runtime' "$report"
          grep -Fxq 'effect=node.lifecycle' "$report"
          grep -Fxq 'transition=crash' "$report"
          grep -Eq '^observed_icount=[1-9][0-9]*$' "$report"
          grep -Eq '^action=[0-9a-f]{64}$' "$report"
          grep -Eq '^evidence=[0-9a-f]{64}$' "$report"
          grep -Fxq 'exit_code=70' "$report"
          grep -Fxq 'lifecycle_impulse_committed=true' "$report"

          prefix_modifications=${qemuWithoutTypedResult}/share/licenses/qemu-crucible-without-typed-node-result/AOS-MODIFICATIONS
          grep -Fxq 'Distribution status: non-distributable compatibility-test material' \
            "$prefix_modifications"
          if grep -Fq 'Corresponding source package:' "$prefix_modifications"; then
            echo 'FAIL: the compatibility-only QEMU prefix claims full-series corresponding source' >&2
            exit 1
          fi
          prefix_policy=${qemuWithoutTypedResult}/nix-support/aos-release-policy
          grep -Fxq 'artifact_role=internal-component' "$prefix_policy"
          grep -Fxq 'standalone_release=false' "$prefix_policy"
          grep -Fxq 'release_via=none-test-only' "$prefix_policy"
          grep -Fxq 'corresponding_source_required=true' "$prefix_policy"
          grep -Fxq 'publishable=false' "$prefix_policy"

          # Keep the base short enough for the nested QMP Unix socket path.
          without_result_dir="$TMPDIR/no0072"
          mkdir -p "$without_result_dir"
          without_result_stdout="$TMPDIR/live-node-lifecycle-without-typed-result.stdout"
          without_result_stderr="$TMPDIR/live-node-lifecycle-without-typed-result.stderr"
          if timeout -k 15 590 \
            "$TMPDIR/live-node-lifecycle-target/debug/examples/crucible-qemu-live-node-lifecycle-fault" \
            ${qemuWithoutTypedResult}/bin/qemu-system-x86_64 \
            ${pluginWithoutTypedResult}/lib/libcrucible_qemu_plugin.so \
            "$vmlinuz" \
            "${qemuWithoutTypedResult}/share/qemu/bios-256k.bin" \
            "$without_result_dir" \
            > "$without_result_stdout" 2> "$without_result_stderr"; then
            echo 'FAIL: the live gate accepted QEMU without patch 0072' >&2
            exit 1
          fi
          grep -Fq 'production typed result rejection' "$without_result_stderr"
          if grep -Fxq PASS "$without_result_stdout"; then
            echo 'FAIL: the patch-0072 negative emitted PASS' >&2
            exit 1
          fi

          mkdir -p "$out"
          cp "$report" "$out/result"
          cp "$without_result_stderr" "$out/without-typed-node-result.stderr"
          printf 'attr_path=%s\n' "$ATTR_PATH" >> "$out/result"
          printf 'proven=typed-event,binding-evaluation,cross-domain-atomic-commit,exact-capability-replay,shared-command-ring,safe-boundary,changed-state-precondition-rejection,typed-occurrence,authorized-process-exit,patch-0072-required\n' >> "$out/result"
        '';
      }
    ];
  }
