{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase2.gates.patchMicrotests",
  taskIds ? ["T-PKG-4" "T-HARN-20" "T-PATCH-2" "T-PATCH-20" "T-PATCH-21" "T-PATCH-22" "T-PATCH-23" "T-PATCH-24"],
  openTaskIds ? [],
  qemuPackage ? pkgs.qemu-crucible,
  dependencies ? [],
}: let
  patchDir = ../../pkgs/emulation/qemu-patches;
  series = import ../../pkgs/emulation/qemu-patches/_series.nix;
  qemuNix = builtins.readFile ../../pkgs/emulation/qemu.nix;
  defaultNix = builtins.readFile ./default.nix;
  qemuPatchSeries = import ./phase2-qemu-patch-series.nix {inherit pkgs lib;};
  qemuPluginFailLoud = import ./phase2-plugin-fail-loud.nix {inherit pkgs lib;};
  qemuRrQuantumIcount = import ./phase2-qemu-rr-quantum-icount.nix {inherit pkgs lib;};
  qemuDetIpi = import ./phase2-qemu-det-ipi.nix {inherit pkgs lib;};
  qemuVcpuIntrospect = import ./phase2-qemu-vcpu-introspect.nix {inherit pkgs lib;};
  qemuPreemptionInject = import ./phase2-qemu-preemption-inject.nix {inherit pkgs lib;};
  qemuPatchRegeneration = import ./phase2-qemu-patch-regeneration.nix {
    inherit pkgs lib qemuPackage;
  };
  qemuPatchPrefixBuilds = import ./phase2-qemu-patch-prefix-builds.nix {
    inherit pkgs lib qemuPackage;
    attrPath = "${attrPath}.prefixBuilds";
  };
  qemuPatchPrefixAttribution = import ./phase2-qemu-patch-prefix-attribution.nix {
    inherit pkgs lib qemuPackage;
    attrPath = "${attrPath}.prefixAttribution";
  };
  qemuPatchDropOne = import ./phase2-qemu-patch-drop-one.nix {
    inherit pkgs lib qemuPackage;
    attrPath = "${attrPath}.dropOne";
  };
  qemuDoorbellNoPatch = import ./phase1-qemu-doorbell-no-patch.nix {inherit pkgs lib qemuPackage;};
  qemuDiagnosticPatchesDevOnly = import ./phase1-qemu-diagnostic-patches-dev-only.nix {inherit pkgs lib qemuPackage;};
  patchFiles =
    builtins.sort builtins.lessThan
    (builtins.filter
      (name: lib.hasSuffix ".patch" name)
      (builtins.attrNames (builtins.readDir patchDir)));

  perPatchMicrotests = [
    {
      patch = "0001-crucible-sim-accel.patch";
      check = import ./phase1-sim-accel.nix {inherit pkgs lib qemuPackage;};
    }
    {
      patch = "0002-crucible-rr-fingerprint-helpers.patch";
      check = import ./phase1-rr-fingerprint-helpers.nix {inherit pkgs lib qemuPackage;};
    }
    {
      patch = "0003-crucible-icount-no-realtime.patch";
      check = import ./phase1-icount-no-realtime.nix {inherit pkgs lib qemuPackage;};
    }
    {
      patch = "0004-crucible-no-warp-with-plugin.patch";
      check = import ./phase1-no-warp-with-plugin.nix {inherit pkgs lib qemuPackage;};
    }
    {
      patch = "0005-crucible-det-glib-prng.patch";
      check = import ./phase1-qemu-deterministic-entropy.nix {inherit pkgs lib qemuPackage;};
    }
    {
      patch = "0006-crucible-clock-deadline.patch";
      check = import ./phase1-clock-deadline.nix {inherit pkgs lib qemuPackage;};
    }
    {
      patch = "0007-crucible-block-rtc-read.patch";
      check = import ./phase1-block-rtc-read.nix {inherit pkgs lib qemuPackage;};
    }
    {
      patch = "0008-crucible-det-getrandom.patch";
      check = import ./phase1-qemu-deterministic-getrandom.nix {inherit pkgs lib qemuPackage;};
    }
    {
      patch = "0009-crucible-net-deterministic.patch";
      check = import ./phase1-qemu-net-deterministic.nix {inherit pkgs lib qemuPackage;};
    }
    {
      patch = "0010-crucible-plugin-time-advance.patch";
      check = import ./phase1-plugin-time-advance.nix {inherit pkgs lib qemuPackage;};
    }
    {
      patch = "0011-crucible-plugin-icount-raw.patch";
      check = import ./phase1-plugin-runtime-apis.nix {
        inherit pkgs lib qemuPackage;
        patchName = "0011-crucible-plugin-icount-raw.patch";
      };
    }
    {
      patch = "0012-crucible-plugin-vcpu-exit.patch";
      check = import ./phase1-plugin-runtime-apis.nix {
        inherit pkgs lib qemuPackage;
        patchName = "0012-crucible-plugin-vcpu-exit.patch";
      };
    }
    {
      patch = "0013-crucible-plugin-wake-fd.patch";
      check = import ./phase1-plugin-runtime-apis.nix {
        inherit pkgs lib qemuPackage;
        patchName = "0013-crucible-plugin-wake-fd.patch";
      };
    }
    {
      patch = "0014-crucible-plugin-tcg-exec-cb.patch";
      check = import ./phase1-plugin-runtime-apis.nix {
        inherit pkgs lib qemuPackage;
        patchName = "0014-crucible-plugin-tcg-exec-cb.patch";
      };
    }
    {
      patch = "0015-crucible-blk-shmem.patch";
      check = import ./phase1-qemu-block-shmem.nix {
        inherit pkgs lib qemuPackage;
        patchName = "0015-crucible-blk-shmem.patch";
      };
    }
    {
      patch = "0016-crucible-blk-shmem-io-fixes.patch";
      check = import ./phase1-qemu-block-shmem.nix {
        inherit pkgs lib qemuPackage;
        patchName = "0016-crucible-blk-shmem-io-fixes.patch";
      };
    }
    {
      patch = "0017-crucible-blk-write-sentinel.patch";
      check = import ./phase1-qemu-block-shmem.nix {
        inherit pkgs lib qemuPackage;
        patchName = "0017-crucible-blk-write-sentinel.patch";
      };
    }
    {
      patch = "0018-crucible-dev-cb-api.patch";
      check = import ./phase1-qemu-9p-shmem.nix {
        inherit pkgs lib qemuPackage;
        patchName = "0018-crucible-dev-cb-api.patch";
      };
    }
    {
      patch = "0019-crucible-9p-shmem.patch";
      check = import ./phase1-qemu-9p-shmem.nix {
        inherit pkgs lib qemuPackage;
        patchName = "0019-crucible-9p-shmem.patch";
      };
    }
    {
      patch = "0020-crucible-net-tx-callback.patch";
      check = import ./phase1-qemu-net-tx-callback.nix {
        inherit pkgs lib qemuPackage;
        patchName = "0020-crucible-net-tx-callback.patch";
      };
    }
    {
      patch = "0021-crucible-sim-loop-fix.patch";
      check = import ./phase1-qemu-sim-correctness.nix {
        inherit pkgs lib qemuPackage;
        patchName = "0021-crucible-sim-loop-fix.patch";
      };
    }
    {
      patch = "0022-crucible-sim-first-exit.patch";
      check = import ./phase1-qemu-sim-correctness.nix {
        inherit pkgs lib qemuPackage;
        patchName = "0022-crucible-sim-first-exit.patch";
      };
    }
    {
      patch = "0023-crucible-sim-skip-second-events.patch";
      check = import ./phase1-qemu-sim-correctness.nix {
        inherit pkgs lib qemuPackage;
        patchName = "0023-crucible-sim-skip-second-events.patch";
      };
    }
    {
      patch = "0024-crucible-sim-poll-immediate.patch";
      check = import ./phase1-qemu-sim-correctness.nix {
        inherit pkgs lib qemuPackage;
        patchName = "0024-crucible-sim-poll-immediate.patch";
      };
    }
    {
      patch = "0025-crucible-sim-idle-callbacks.patch";
      check = import ./phase1-qemu-sim-correctness.nix {
        inherit pkgs lib qemuPackage;
        patchName = "0025-crucible-sim-idle-callbacks.patch";
      };
    }
    {
      patch = "0026-crucible-sim-shmem-dispatch.patch";
      check = import ./phase1-qemu-sim-correctness.nix {
        inherit pkgs lib qemuPackage;
        patchName = "0026-crucible-sim-shmem-dispatch.patch";
      };
    }
    {
      patch = "0027-crucible-sim-batch-tcg-exec.patch";
      check = import ./phase1-qemu-sim-batch-tcg-exec.nix {
        inherit pkgs lib qemuPackage;
        patchName = "0027-crucible-sim-batch-tcg-exec.patch";
      };
    }
    {
      patch = "0028-crucible-det-ipi.patch";
      check = import ./phase2-qemu-det-ipi.nix {
        inherit pkgs lib qemuPackage;
        patchName = "0028-crucible-det-ipi.patch";
      };
    }
    {
      patch = "0029-crucible-vcpu-introspect.patch";
      check = import ./phase2-qemu-vcpu-introspect.nix {
        inherit pkgs lib qemuPackage;
        patchName = "0029-crucible-vcpu-introspect.patch";
      };
    }
    {
      patch = "0030-crucible-preemption-inject.patch";
      check = import ./phase2-qemu-preemption-inject.nix {
        inherit pkgs lib qemuPackage;
        patchName = "0030-crucible-preemption-inject.patch";
      };
    }
    {
      patch = "0031-crucible-det-rng-delivery.patch";
      check = import ./phase1-qemu-det-rng-delivery.nix {
        inherit pkgs lib qemuPackage;
      };
    }
    {
      patch = "0032-crucible-det-virtio-ioeventfd.patch";
      check = import ./phase1-qemu-det-virtio-ioeventfd.nix {
        inherit pkgs lib qemuPackage;
      };
    }
    {
      patch = "0033-crucible-sim-observer.patch";
      check = import ./phase2-qemu-sim-observer.nix {
        inherit pkgs lib qemuPackage;
      };
    }
    {
      patch = "0034-crucible-safe-fingerprint-boundary.patch";
      check = import ./phase2-qemu-safe-fingerprint-boundary.nix {
        inherit pkgs lib qemuPackage;
      };
    }
    {
      patch = "0035-crucible-process-argv-attestation.patch";
      check = import ./phase2-qemu-process-argv-attestation.nix {
        inherit pkgs lib qemuPackage;
      };
    }
    {
      patch = "0036-crucible-raw-state-export.patch";
      check = import ./phase2-qemu-raw-state-export.nix {
        inherit pkgs lib qemuPackage;
      };
    }
    {
      patch = "0037-crucible-sim-freeze-warp-at-observation-boundary.patch";
      check = import ./phase2-qemu-sim-warp-freeze.nix {
        inherit pkgs lib qemuPackage;
      };
    }
    {
      patch = "0038-crucible-sim-gate-rr-kick.patch";
      check = import ./phase2-qemu-sim-rr-kick-gate.nix {
        inherit pkgs lib qemuPackage;
      };
    }
    {
      patch = "0039-crucible-blk-device-completion-advance.patch";
      check = import ./phase2-qemu-device-completion-advance.nix {
        inherit pkgs lib qemuPackage;
      };
    }
    {
      patch = "0040-crucible-9p-sync-kick.patch";
      check = import ./phase2-qemu-9p-sync-kick.nix {
        inherit pkgs lib qemuPackage;
      };
    }
    {
      patch = "0041-crucible-whitebox-guest-write.patch";
      check = import ./phase2-qemu-whitebox-guest-write.nix {
        inherit pkgs lib qemuPackage;
      };
    }
    {
      patch = "0042-crucible-aarch64-det-ipi-adapter.patch";
      check = import ./phase2-qemu-aarch64-det-ipi-adapter.nix {
        inherit pkgs lib qemuPackage;
      };
    }
    {
      patch = "0043-crucible-time-advance-commit-barrier.patch";
      check = import ./phase1-plugin-time-advance.nix {inherit pkgs lib qemuPackage;};
    }
    {
      patch = "0044-crucible-time-advance-enqueue-kick.patch";
      check = import ./phase1-plugin-time-advance.nix {inherit pkgs lib qemuPackage;};
    }
    {
      patch = "0045-crucible-time-advance-arm-at-vcpu-boundary.patch";
      check = import ./phase1-plugin-time-advance.nix {inherit pkgs lib qemuPackage;};
    }
    {
      patch = "0046-crucible-translation-prefetch-helper.patch";
      gateField = "patch_microtest_gate";
      check = import ./phase7-translation-prefetch-neutrality.nix {
        inherit pkgs lib;
      };
    }
    {
      patch = "0047-crucible-fault-command-abi.patch";
      check = import ./phase2-qemu-fault-boundary.nix {
        inherit pkgs lib qemuPackage;
        patchName = "0047-crucible-fault-command-abi.patch";
      };
    }
    {
      patch = "0048-crucible-fault-safe-boundary.patch";
      check = import ./phase2-qemu-fault-boundary.nix {
        inherit pkgs lib qemuPackage;
        patchName = "0048-crucible-fault-safe-boundary.patch";
      };
    }
    {
      patch = "0049-crucible-memory-boundary-mutate.patch";
      check = import ./phase2-qemu-memory-mutation.nix {
        inherit pkgs lib qemuPackage;
      };
    }
    {
      patch = "0050-crucible-memory-access-faults.patch";
      check = import ./phase2-qemu-memory-access.nix {
        inherit pkgs lib qemuPackage;
      };
    }
    {
      patch = "0051-crucible-add-architecture-register-fault-mutations.patch";
      check = import ./phase2-qemu-register-mutation.nix {
        inherit pkgs lib qemuPackage;
      };
    }
    {
      patch = "0052-crucible-instruction-and-exception-faults.patch";
      check = import ./phase2-qemu-instruction-faults.nix {
        inherit pkgs lib qemuPackage;
      };
    }
    {
      patch = "0053-crucible-interrupt-faults.patch";
      check = import ./phase2-qemu-interrupt-faults.nix {
        inherit pkgs lib qemuPackage;
      };
    }
    {
      patch = "0054-crucible-inject-architecture-hardware-errors.patch";
      check = import ./phase2-qemu-hardware-error-faults.nix {
        inherit pkgs lib qemuPackage;
      };
    }
    {
      patch = "0055-crucible-vcpu-service-control.patch";
      check = import ./phase2-qemu-vcpu-service.nix {
        inherit pkgs lib qemuPackage;
      };
    }
    {
      patch = "0056-crucible-node-lifecycle-faults.patch";
      check = import ./phase2-qemu-node-lifecycle.nix {
        inherit pkgs lib qemuPackage;
      };
    }
    {
      patch = "0060-crucible-block-typed-errors.patch";
      check = import ./phase1-qemu-block-shmem.nix {
        inherit pkgs lib qemuPackage;
        patchName = "0060-crucible-block-typed-errors.patch";
      };
    }
    {
      patch = "0061-crucible-block-discard.patch";
      check = import ./phase1-qemu-block-shmem.nix {
        inherit pkgs lib qemuPackage;
        patchName = "0061-crucible-block-discard.patch";
      };
    }
    {
      patch = "0062-crucible-block-transport-reset.patch";
      check = import ./phase1-qemu-block-shmem.nix {
        inherit pkgs lib qemuPackage;
        patchName = "0062-crucible-block-transport-reset.patch";
      };
    }
    {
      patch = "0063-crucible-plugin-vmstop.patch";
      check = import ./phase1-plugin-runtime-apis.nix {
        inherit pkgs lib qemuPackage;
        patchName = "0063-crucible-plugin-vmstop.patch";
      };
    }
    {
      patch = "0064-crucible-terminal-lifecycle-completion.patch";
      check = import ./phase2-qemu-terminal-lifecycle.nix {
        inherit pkgs lib qemuPackage;
        patchName = "0064-crucible-terminal-lifecycle-completion.patch";
      };
    }
    {
      patch = "0065-crucible-authenticated-terminal-lifecycle.patch";
      check = import ./phase2-qemu-terminal-lifecycle.nix {
        inherit pkgs lib qemuPackage;
        patchName = "0065-crucible-authenticated-terminal-lifecycle.patch";
      };
    }
    {
      patch = "0066-crucible-immutable-process-generation.patch";
      check = import ./phase2-qemu-terminal-lifecycle.nix {
        inherit pkgs lib qemuPackage;
        patchName = "0066-crucible-immutable-process-generation.patch";
      };
    }
    {
      patch = "0067-crucible-serialize-and-harden-core-fault-state.patch";
      check = import ./phase2-qemu-fault-vmstate.nix {
        inherit pkgs lib qemuPackage;
        patchName = "0067-crucible-serialize-and-harden-core-fault-state.patch";
      };
    }
    {
      patch = "0068-crucible-guest-clock-faults.patch";
      check = import ./phase2-qemu-fault-vmstate.nix {
        inherit pkgs lib qemuPackage;
        patchName = "0068-crucible-guest-clock-faults.patch";
      };
    }
    {
      patch = "0069-crucible-accelerator-fault-device.patch";
      check = import ./phase2-qemu-fault-vmstate.nix {
        inherit pkgs lib qemuPackage;
        patchName = "0069-crucible-accelerator-fault-device.patch";
      };
    }
    {
      patch = "0070-crucible-fault-vmstate.patch";
      check = import ./phase2-qemu-fault-vmstate.nix {
        inherit pkgs lib qemuPackage;
        patchName = "0070-crucible-fault-vmstate.patch";
      };
    }
    {
      patch = "0071-crucible-lifecycle-precondition.patch";
      check = import ./phase2-qemu-fault-vmstate.nix {
        inherit pkgs lib qemuPackage;
        patchName = "0071-crucible-lifecycle-precondition.patch";
      };
    }
    {
      patch = "0072-crucible-typed-node-result-schema.patch";
      check = import ./phase2-qemu-fault-vmstate.nix {
        inherit pkgs lib qemuPackage;
        patchName = "0072-crucible-typed-node-result-schema.patch";
      };
    }
    {
      patch = "0073-crucible-device-wait-vmstop.patch";
      check = import ./phase1-plugin-runtime-apis.nix {
        inherit pkgs lib qemuPackage;
        patchName = "0073-crucible-device-wait-vmstop.patch";
      };
    }
    {
      patch = "0074-crucible-arm-accelerator-result-opportunities.patch";
      check = import ./phase2-qemu-fault-vmstate.nix {
        inherit pkgs lib qemuPackage;
        patchName = "0074-crucible-arm-accelerator-result-opportunities.patch";
      };
    }
    {
      patch = "0075-crucible-restore-authenticated-fault-event-requests.patch";
      check = import ./phase2-qemu-fault-vmstate.nix {
        inherit pkgs lib qemuPackage;
        patchName = "0075-crucible-restore-authenticated-fault-event-requests.patch";
      };
    }
    {
      patch = "0076-crucible-9p-completion-wake-registration.patch";
      check = import ./phase1-qemu-9p-shmem.nix {
        inherit pkgs lib qemuPackage;
        patchName = "0076-crucible-9p-completion-wake-registration.patch";
      };
    }
  ];

  microtestPatchNames =
    builtins.sort builtins.lessThan (map (test: test.patch) perPatchMicrotests);

  inherit (import ./_lib.nix {inherit lib;}) hasInfix;

  qemuNixAppliesManifestSeries =
    hasInfix "patchCommand = file:" qemuNix
    && hasInfix "builtins.concatStringsSep \"\" (map patchCommand series.patchFiles)" qemuNix;

  missingMicrotests =
    builtins.filter (patch: !(builtins.elem patch microtestPatchNames)) patchFiles;
  staleMicrotests =
    builtins.filter (patch: !(builtins.elem patch patchFiles)) microtestPatchNames;
  qemuInertRedGateWired =
    hasInfix "qemuInert = redGate {" defaultNix
    && hasInfix ''gateName = "gate:qemu-inert";'' defaultNix
    && hasInfix "dependencies = [patchMicrotestsCheck];" defaultNix
    && hasInfix "patchMicrotests = patchMicrotestsCheck;" defaultNix;
  qemuInertImplementedGateWired =
    hasInfix "qemuInert = greenBeforeAdvance {" defaultNix
    && hasInfix ''attrPath = "checks.crucible.phase2.gates.qemuInert";'' defaultNix
    && hasInfix "gate = import ./phase2-qemu-inert.nix" defaultNix
    && hasInfix "patchMicrotests = patchMicrotests.rawGate;" defaultNix
    && hasInfix "dependencies = [patchMicrotests.rawGate];" defaultNix;
  qemuInertGateUnwired = !(qemuInertRedGateWired || qemuInertImplementedGateWired);

  staticFailures =
    map (patch: "pkgs/emulation/qemu-patches/${patch}: carried patch has no per-patch micro-test")
    missingMicrotests
    ++ map (patch: "tests/crucible/phase2-patch-microtests.nix: stale micro-test for absent patch ${patch}")
    staleMicrotests
    ++ lib.optionals (!qemuNixAppliesManifestSeries) [
      "pkgs/emulation/qemu.nix: QEMU patch phase must be generated from qemu-patches/_series.nix"
    ]
    ++ lib.optionals qemuInertGateUnwired [
      "tests/crucible/default.nix: phase2 gate:qemu-inert is not wired into the patch CI dependency surface"
    ];

  resultChecks =
    lib.concatMapStringsSep "\n" (test: ''
      result="${test.check}/result"
      cp "$result" "$out/per-patch/${test.patch}.result"
      grep -q '^PASS$' "$result"
      grep -q '^${test.gateField or "gate"}=gate:patch-microtests$' "$result"
      grep -q '^patch=${test.patch}$' "$result"
      grep -q '^patched_fixture_exercised=true$' "$result"
      grep -q '^stock_negative_control=true$' "$result"
      grep -q '^qemu_package=${qemuPackage}$' "$result"
      grep -q '^qemu_package_version=${qemuPackage.version}$' "$result"
    '')
    perPatchMicrotests;
in
  if staticFailures != []
  then throw "crucible phase2 patch-microtests gate failed:\n${builtins.concatStringsSep "\n" staticFailures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase2-patch-microtests";
      version = "0";
      src = null;

      buildDeps =
        [
          pkgs.binutils
          pkgs.coreutils
          pkgs.grep
          pkgs.patch
          pkgs.tar
          pkgs.xz
        ]
        ++ dependencies;

      phases = [
        {
          name = "aggregate-patch-microtests";
          script = ''
            set -eu

            mkdir -p "$out/per-patch"

            work_dir="$PWD"
            apply_dir="$TMPDIR/qemu-patch-apply-clean"
            mkdir -p "$apply_dir"
            tar -xf ${qemuPackage.src} -C "$apply_dir"
            cd "$apply_dir/qemu-${qemuPackage.version}"
            for patch in ${builtins.concatStringsSep " " patchFiles}; do
              patch --batch --forward --fuzz=0 -p1 -i "${patchDir}/$patch"
            done
            cd "$work_dir"

            test -x ${qemuPackage}/bin/qemu-system-x86_64
            test -f ${qemuPackage}/include/qemu/qemu-plugin.h
            nm -D --defined-only ${qemuPackage}/bin/qemu-system-x86_64 \
              > "$out/qemu-system-x86_64.dynamic-symbols"
            for symbol in \
              qemu_plugin_clock_deadline_ns \
              qemu_plugin_net_inject \
              qemu_plugin_net_send \
              qemu_plugin_net_flush \
              qemu_plugin_net_can_receive \
              qemu_plugin_register_net_tx_cb \
              qemu_plugin_has_time_control \
              qemu_plugin_register_time_advance_cb \
              qemu_plugin_advance_time_ns \
              qemu_plugin_icount_raw \
              qemu_plugin_icount_at_tb_entry \
              qemu_plugin_force_vcpu_exit \
              qemu_plugin_crucible_single_threaded_rr \
              qemu_plugin_register_wake_fd \
              qemu_plugin_request_shutdown \
              qemu_plugin_register_tcg_exec_cb \
              qemu_plugin_register_vcpu_idle_resume_cb \
              qemu_plugin_register_sim_shmem_dispatch_cb \
              qemu_plugin_register_sim_shmem_observer_cb \
              qemu_plugin_crucible_register_ipi_delivery_cb \
              qemu_plugin_read_vcpu_regs \
              qemu_plugin_rr_cursor \
              qemu_plugin_inject_preemption \
              qemu_plugin_register_blk_cb \
              qemu_plugin_register_blk_wait_cb \
              qemu_plugin_register_9p_cb
            do
              grep -E "[[:space:]]$symbol$" "$out/qemu-system-x86_64.dynamic-symbols"
            done

            cp "${qemuPatchSeries}/result" "$out/patch-series.result"
            grep -q '^PASS$' "$out/patch-series.result"
            cp "${qemuPatchPrefixBuilds}/result" "$out/patch-prefix-builds.result"
            cp "${qemuPatchPrefixBuilds}/prefix-provenance.tsv" "$out/prefix-provenance.tsv"
            grep -q '^PASS$' "$out/patch-prefix-builds.result"
            grep -q '^gate=gate:patch-microtests$' "$out/patch-prefix-builds.result"
            grep -q '^prefix_count=${toString (builtins.length patchFiles)}$' "$out/patch-prefix-builds.result"
            grep -q '^prefix_model=compile-free-deterministic-git-provenance-plus-full-series-build$' "$out/patch-prefix-builds.result"
            grep -q '^series_not_compile_ordered_per_prefix_build_infeasible=true$' "$out/patch-prefix-builds.result"
            grep -q '^prefix_manifest_columns=index,patch,commit,tree,patch_sha256$' "$out/patch-prefix-builds.result"
            grep -q '^every_patch_prefix_apply_clean=true$' "$out/patch-prefix-builds.result"
            grep -q '^every_patch_prefix_apply_fuzz=0$' "$out/patch-prefix-builds.result"
            grep -q '^every_patch_prefix_commit_verified=true$' "$out/patch-prefix-builds.result"
            grep -q '^every_patch_prefix_tree_verified=true$' "$out/patch-prefix-builds.result"
            grep -q '^patch_branch_head_commit_verified=true$' "$out/patch-prefix-builds.result"
            grep -q '^full_series_qemu_system_build=true$' "$out/patch-prefix-builds.result"
            grep -q '^full_series_build_is_shipped_qemu_crucible=true$' "$out/patch-prefix-builds.result"
            grep -q '^qemu_block_utilities_link_at_full_series=true$' "$out/patch-prefix-builds.result"
            grep -q '^crucible_shmem_registration_symbol_present_at_full_series=true$' "$out/patch-prefix-builds.result"
            grep -q '^generated_shmem_header_hash_verified=true$' "$out/patch-prefix-builds.result"
            grep -q '^prefix_manifest_records_patch_hash=true$' "$out/patch-prefix-builds.result"
            grep -q '^prefix_manifest_records_branch_commit=true$' "$out/patch-prefix-builds.result"
            grep -q '^prefix_manifest_records_branch_tree=true$' "$out/patch-prefix-builds.result"
            cp "${qemuPatchPrefixAttribution}/result" "$out/patch-prefix-attribution.result"
            cp -r "${qemuPatchPrefixAttribution}/attribution" "$out/prefix-attribution"
            grep -q '^PASS$' "$out/patch-prefix-attribution.result"
            grep -q '^gate=gate:patch-microtests$' "$out/patch-prefix-attribution.result"
            grep -q '^per_patch_effect_appears_at_prefix_n_not_n_minus_1=true$' "$out/patch-prefix-attribution.result"
            grep -q '^exported_symbols_monotonic_across_prefixes=true$' "$out/patch-prefix-attribution.result"
            grep -q '^sim_accelerator_first_appears_at_prefix_1_only=true$' "$out/patch-prefix-attribution.result"
            grep -q '^source_declared_crucible_exports_equal_shipped_binary_exports=true$' "$out/patch-prefix-attribution.result"
            grep -q '^every_crucible_symbol_attributed_to_exactly_one_prefix=true$' "$out/patch-prefix-attribution.result"
            grep -q '^interface_patches_strictly_attributed=true$' "$out/patch-prefix-attribution.result"
            grep -q '^recorded_patches_source_tree_attributed=true$' "$out/patch-prefix-attribution.result"
            grep -q '^sim_off_inertness_surface_is_opt_in_and_monotonic=true$' "$out/patch-prefix-attribution.result"
            cp "${qemuPatchDropOne}/result" "$out/patch-drop-one.result"
            cp -r "${qemuPatchDropOne}/per-patch" "$out/drop-one-per-patch"
            cp "${qemuPatchDropOne}/methods.tsv" "$out/drop-one-methods.tsv"
            grep -q '^PASS$' "$out/patch-drop-one.result"
            grep -q '^gate=gate:patch-microtests$' "$out/patch-drop-one.result"
            grep -q '^every_patch_has_exactly_one_drop_one_method=true$' "$out/patch-drop-one.result"
            grep -q '^clean_conflict_split_recomputed_live=true$' "$out/patch-drop-one.result"
            grep -q '^drop_one_composition_count=0$' "$out/patch-drop-one.result"
            grep -q '^structural_fallback_count=0$' "$out/patch-drop-one.result"
            cp "${qemuPatchRegeneration}/result" "$out/patch-regeneration.result"
            grep -q '^PASS$' "$out/patch-regeneration.result"
            grep -q '^gate=gate:patch-microtests$' "$out/patch-regeneration.result"
            grep -q '^patch_regeneration_from_tracked_stack=true$' "$out/patch-regeneration.result"
            grep -q '^regenerated_patch_bytes_match_committed=true$' "$out/patch-regeneration.result"
            grep -q '^patch_branch_bundle_verified=true$' "$out/patch-regeneration.result"
            grep -q '^patch_branch_commit_hashes_match_manifest=true$' "$out/patch-regeneration.result"
            grep -q '^apply_clean_regenerated_series=true$' "$out/patch-regeneration.result"
            grep -q '^qemu_package_patch_phase_generated_from_manifest=true$' "$out/patch-regeneration.result"
            grep -q '^qemu_build_identity_metadata_installed=true$' "$out/patch-regeneration.result"
            grep -q '^qemu_build_id_material_includes=qemu_version,qemu_source_hash,qemu_nix_hash,qemu_configure_flags_hash,patch_series_hash,patch_branch_bundle_hash,patch_branch_material_hash,qemu_shmem_abi_version,qemu_shmem_header_hash$' "$out/patch-regeneration.result"
            grep -q '^artifact_build_id_match=true$' "$out/patch-regeneration.result"
            grep -q '^artifact_validator_rejects_mismatch=true$' "$out/patch-regeneration.result"
            grep -q '^artifact_mismatch_regates=true$' "$out/patch-regeneration.result"
            grep -q '^qemu_version_bump_regate_enforced=true$' "$out/patch-regeneration.result"
            cp "${qemuPluginFailLoud}/result" "$out/qemu-plugin-fail-loud.result"
            grep -q '^PASS$' "$out/qemu-plugin-fail-loud.result"
            grep -q '^missing_capability=distinct-errors$' "$out/qemu-plugin-fail-loud.result"
            grep -q '^wall_clock_fallback=forbidden$' "$out/qemu-plugin-fail-loud.result"
            cp "${qemuRrQuantumIcount}/result" "$out/qemu-rr-quantum-icount.result"
            grep -q '^PASS$' "$out/qemu-rr-quantum-icount.result"
            grep -q '^accelerator=sim,thread=single$' "$out/qemu-rr-quantum-icount.result"
            grep -q '^vcpus=2$' "$out/qemu-rr-quantum-icount.result"
            grep -q '^sim_s11_trace_source=checks.crucible.phase0.s11MultiVcpuFingerprint(accelerator=sim,thread=single,stop_at=4194304)$' "$out/qemu-rr-quantum-icount.result"
            grep -q '^cross_run_switch_icount_trace_match=true$' "$out/qemu-rr-quantum-icount.result"
            grep -q '^cross_run_per_vcpu_delta_trace_match=true$' "$out/qemu-rr-quantum-icount.result"
            grep -q '^adaptive_realtime_quantum_negative_control=red$' "$out/qemu-rr-quantum-icount.result"
            grep -q '^adaptive_rr_switch_trace_negative_control=red$' "$out/qemu-rr-quantum-icount.result"
            grep -q '^patched_non_sim_rr_switch_trace_negative_control=red$' "$out/qemu-rr-quantum-icount.result"
            grep -q '^non_sim_rr_switch_quantum_uses_stock_budget=true$' "$out/qemu-rr-quantum-icount.result"
            cp "${qemuDetIpi}/result" "$out/qemu-det-ipi.result"
            grep -q '^PASS$' "$out/qemu-det-ipi.result"
            grep -q '^deterministic_ipi_rr_handoff=queued-drain-before-next-vcpu$' "$out/qemu-det-ipi.result"
            grep -q '^deterministic_ipi_fixed_mode_trace=true$' "$out/qemu-det-ipi.result"
            grep -q '^deterministic_ipi_init_mode_trace=true$' "$out/qemu-det-ipi.result"
            grep -q '^deterministic_ipi_sipi_mode_trace=true$' "$out/qemu-det-ipi.result"
            grep -q '^deterministic_ipi_event_count_match=true$' "$out/qemu-det-ipi.result"
            grep -q '^deterministic_ipi_delivery_icount_trace_match=true$' "$out/qemu-det-ipi.result"
            grep -q '^deterministic_ipi_source_target_distinct=true$' "$out/qemu-det-ipi.result"
            cp "${qemuVcpuIntrospect}/result" "$out/qemu-vcpu-introspect.result"
            grep -q '^PASS$' "$out/qemu-vcpu-introspect.result"
            grep -q '^formal_register_export=qemu_plugin_read_vcpu_regs$' "$out/qemu-vcpu-introspect.result"
            grep -q '^formal_cursor_export=qemu_plugin_rr_cursor$' "$out/qemu-vcpu-introspect.result"
            grep -q '^arbitrary_vcpu_register_read=true$' "$out/qemu-vcpu-introspect.result"
            grep -q '^register_read_side_effect_free=true$' "$out/qemu-vcpu-introspect.result"
            grep -q '^register_short_buffer_fails_closed=true$' "$out/qemu-vcpu-introspect.result"
            grep -q '^register_size_mismatch_rejected=true$' "$out/qemu-vcpu-introspect.result"
            grep -q '^rr_cursor_reads_current_vcpu_position_and_quantum=true$' "$out/qemu-vcpu-introspect.result"
            grep -q '^rr_cursor_boundary_rejected=true$' "$out/qemu-vcpu-introspect.result"
            grep -q '^rr_cursor_out_of_range_current_vcpu_rejected=true$' "$out/qemu-vcpu-introspect.result"
            cp "${qemuPreemptionInject}/result" "$out/qemu-preemption-inject.result"
            grep -q '^PASS$' "$out/qemu-preemption-inject.result"
            grep -q '^formal_preemption_export=qemu_plugin_inject_preemption$' "$out/qemu-preemption-inject.result"
            grep -q '^vcpu_switch_cross_run_icount_match=true$' "$out/qemu-preemption-inject.result"
            grep -q '^interrupt_cross_run_icount_match=true$' "$out/qemu-preemption-inject.result"
            grep -q '^out_of_window_rejected_distinctly=true$' "$out/qemu-preemption-inject.result"
            grep -q '^before_deadline_rejected_distinctly=true$' "$out/qemu-preemption-inject.result"
            grep -q '^past_icount_rejected_distinctly=true$' "$out/qemu-preemption-inject.result"
            grep -q '^invalid_window_rejected_distinctly=true$' "$out/qemu-preemption-inject.result"
            grep -q '^duplicate_pending_rejected_distinctly=true$' "$out/qemu-preemption-inject.result"
            grep -q '^preemption_budget_clamped_to_commanded_icount=true$' "$out/qemu-preemption-inject.result"
            grep -q '^preemption_no_clamp_no_defer_on_invalid_window=true$' "$out/qemu-preemption-inject.result"
            grep -q '^commanded_interrupt_delivered_as_apic_fixed_vector=true$' "$out/qemu-preemption-inject.result"
            grep -q '^real_qemu_patch_apply_clean=true$' "$out/qemu-preemption-inject.result"
            grep -q '^stock_negative_control_symbols_absent=true$' "$out/qemu-preemption-inject.result"
            cp "${qemuDoorbellNoPatch}/result" "$out/qemu-doorbell-no-patch.result"
            grep -q '^PASS$' "$out/qemu-doorbell-no-patch.result"
            grep -q '^gate=gate:patch-microtests$' "$out/qemu-doorbell-no-patch.result"
            grep -q '^qemu_doorbell_patch_required=false$' "$out/qemu-doorbell-no-patch.result"
            grep -q '^bespoke_qemu_doorbell_patch_present=false$' "$out/qemu-doorbell-no-patch.result"
            grep -q '^phase0_s5_virtual_read_validated=true$' "$out/qemu-doorbell-no-patch.result"
            grep -q '^phase0_s2_io_trap_surface_validated=true$' "$out/qemu-doorbell-no-patch.result"
            grep -q '^whitebox_mode_off_installs_no_trap_validated=true$' "$out/qemu-doorbell-no-patch.result"
            cp "${qemuDiagnosticPatchesDevOnly}/result" "$out/qemu-diagnostic-patches-dev-only.result"
            grep -q '^PASS$' "$out/qemu-diagnostic-patches-dev-only.result"
            grep -q '^gate=gate:patch-microtests$' "$out/qemu-diagnostic-patches-dev-only.result"
            grep -q '^qemu_diagnostic_patches_shipped=false$' "$out/qemu-diagnostic-patches-dev-only.result"
            grep -q '^crucible_tcg_exec_diag_shipped=false$' "$out/qemu-diagnostic-patches-dev-only.result"
            grep -q '^crucible_virtserial_socket_shipped=false$' "$out/qemu-diagnostic-patches-dev-only.result"
            grep -q '^dev_only_diagnostic_patches_inert_by_default=true$' "$out/qemu-diagnostic-patches-dev-only.result"

            ${resultChecks}

            cat > "$out/result" <<'RESULT'
            PASS
            check=${attrPath}
            tasks=${builtins.concatStringsSep "," taskIds}
            open_tasks=${builtins.concatStringsSep "," openTaskIds}
            status=complete
            evidence_scope=per-patch-prefix-provenance-plus-live-drop-one-semantics
            gate=gate:patch-microtests
            patch_count=${toString (builtins.length patchFiles)}
            microtest_count=${toString (builtins.length perPatchMicrotests)}
            patches=${builtins.concatStringsSep "," patchFiles}
            patch_series_gate_passed=true
            patch_prefix_build_gate_passed=true
            patch_prefix_provenance_is_compile_free=true
            series_not_compile_ordered_per_prefix_build_infeasible=true
            patch_prefix_attribution_gate_passed=true
            per_patch_effect_attributed_to_its_own_prefix=true
            per_patch_effect_appears_at_prefix_n_not_n_minus_1=true
            per_patch_sim_off_inertness_surface_opt_in_and_monotonic=true
            patch_drop_one_gate_passed=true
            every_patch_has_exactly_one_drop_one_grade_attribution=true
            drop_one_clean_conflict_split_recomputed_live=true
            drop_one_composition_count=0
            structural_fallback_count=0
            drop_one_methods_manifest=drop-one-methods.tsv
            interface_patches_strictly_attributed_by_symbol_first_appearance=true
            recorded_patches_source_attributed_by_unique_prefix_tree=true
            per_prefix_runtime_sim_mode_boot_infeasible_before_full_sim_loop=recorded-bound
            per_patch_full_stack_semantic_microtests_target=fully-patched-qemu-package
            every_patch_prefix_apply_clean=true
            every_patch_prefix_commit_verified=true
            every_patch_prefix_tree_verified=true
            full_series_qemu_system_build=true
            qemu_block_utilities_link_at_full_series=true
            crucible_shmem_registration_symbol_present_at_full_series=true
            generated_shmem_header_hash_verified=true
            prefix_manifest_records_patch_hash=true
            prefix_manifest_records_branch_commit=true
            prefix_manifest_records_branch_tree=true
            prefix_manifest=prefix-provenance.tsv
            patch_regeneration_gate_passed=true
            patch_regeneration_drift_checked=true
            patch_regeneration_result_consumed=true
            qemu_build_identity_artifact_checked=true
            qemu_version_bump_regate_enforced=true
            qemu_package_patch_phase_generated_from_manifest=true
            qemu_plugin_fail_loud_gate_passed=true
            missing_required_capability_fails_loud=true
            qemu_rr_quantum_icount_gate_passed=true
            cross_run_switch_icount_trace_match=true
            cross_run_per_vcpu_delta_trace_match=true
            adaptive_realtime_quantum_negative_control=red
            adaptive_rr_switch_trace_negative_control=red
            patched_non_sim_rr_switch_trace_negative_control=red
            non_sim_rr_switch_quantum_uses_stock_budget=true
            qemu_det_ipi_gate_passed=true
            deterministic_ipi_fixed_mode_trace=true
            deterministic_ipi_init_mode_trace=true
            deterministic_ipi_sipi_mode_trace=true
            deterministic_ipi_delivery_icount_trace_match=true
            qemu_vcpu_introspect_gate_passed=true
            formal_vcpu_register_export_present=true
            formal_rr_cursor_export_present=true
            arbitrary_vcpu_register_read=true
            register_read_side_effect_free=true
            register_size_mismatch_rejected=true
            rr_cursor_boundary_rejected=true
            rr_cursor_out_of_range_current_vcpu_rejected=true
            qemu_preemption_inject_gate_passed=true
            formal_preemption_export_present=true
            commanded_vcpu_switch_cross_run_icount_match=true
            commanded_interrupt_cross_run_icount_match=true
            out_of_window_preemption_rejected_distinctly=true
            before_deadline_preemption_rejected_distinctly=true
            preemption_budget_clamped_to_commanded_icount=true
            qemu_doorbell_no_patch_gate_passed=true
            qemu_diagnostic_patches_dev_only_gate_passed=true
            apply_clean_pinned_qemu=true
            apply_clean_patch_fuzz=0
            patched_qemu_package_build_passed=true
            patched_qemu_package=${qemuPackage}
            patched_qemu_package_version=${qemuPackage.version}
            plugin_exports_dynamic_symbols_checked=true
            qemu_plugin_clock_deadline_export_present=true
            qemu_plugin_net_exports_present=true
            qemu_plugin_time_drain_exports_present=true
            qemu_plugin_runtime_api_exports_present=true
            qemu_plugin_sim_correctness_exports_present=true
            qemu_plugin_det_ipi_exports_present=true
            qemu_plugin_vcpu_introspection_exports_present=true
            qemu_plugin_preemption_inject_export_present=true
            qemu_plugin_block_exports_present=true
            qemu_plugin_9p_exports_present=true
            qemu_inert_gate_attr=checks.crucible.phase2.gates.qemuInert
            qemu_inert_gate_wired=true
            qemu_inert_depends_on_patch_microtests=true
            qemu_inert_gate_dependency=gate:qemu-inert->gate:patch-microtests
            qemu_inert_full_corpus_task=T-PATCH-3
            every_carried_patch_has_microtest=true
            every_microtest_keyed_to_patched_qemu_package=true
            every_microtest_exercises_patched_fixture=true
            every_microtest_has_stock_negative_control=true
            no_patch_decision_has_microtest_gate=true
            diagnostic_only_patches_excluded_from_shipped_qemu=true
            qemu_package_applies_every_carried_patch=true
            RESULT
          '';
        }
      ];
      passthru.dropOne = qemuPatchDropOne;
    }
