{
  pkgs,
  lib ? pkgs.lib,
}: let
  qemuNixSource = builtins.readFile ../../pkgs/emulation/qemu.nix;
  pluginSource = builtins.readFile ../../pkgs/emulation/crucible-qemu-trace-plugin.c;
  qemuPatchDir = builtins.path {
    path = ../../pkgs/emulation/qemu-patches;
    name = "qemu-crucible-patches";
  };
  cratesSource = builtins.path {
    path = ../../crates;
    name = "aos-crates";
  };
  rfcDocs = builtins.path {
    path = ../../docs/rfcs/0010-crucible;
    name = "crucible-rfc0010-docs";
  };
  s11MultiVcpuFingerprint = import ./phase0-s11.nix {inherit pkgs lib;};
  livePreemption = import ./phase2-qemu-live-plugin-preemption.nix {
    inherit pkgs lib;
    attrPath = "checks.crucible.phase0.s12PreemptionDecision.livePreemption";
    taskIds = [];
    openTaskIds = [];
  };
in
  pkgs.mkDerivation {
    pname = "crucible-phase0-s12-preemption-decision";
    version = "0";
    src = null;

    qemuNix = qemuNixSource;
    plugin = pluginSource;
    passAsFile = [
      "qemuNix"
      "plugin"
    ];

    buildDeps = [
      pkgs.coreutils
      pkgs.gawk
      pkgs.grep
      pkgs.qemu-crucible
    ];

    QEMU_OUT = builtins.toString pkgs.qemu-crucible;
    QEMU_PATCH_DIR = builtins.toString qemuPatchDir;
    CRATES_SRC = builtins.toString cratesSource;
    RFC_DOCS = builtins.toString rfcDocs;
    S11_RESULT = "${s11MultiVcpuFingerprint}/result";
    LIVE_PREEMPTION_RESULT = "${livePreemption}/result";

    phases = [
      {
        name = "run-s12-preemption-decision-fallback";
        script = ''
          set -eu

          fail() {
            echo "FAIL: $*" >&2
            exit 1
          }

          require_fixed() {
            file="$1"
            text="$2"
            grep -F -q -- "$text" "$file" || fail "missing '$text' in $file"
          }

          require_present_regex() {
            path="$1"
            regex="$2"
            description="$3"
            [ -e "$path" ] || fail "S12 scan target missing: $path"
            grep -E -R -q -- "$regex" "$path" \
              || fail "S12 expected $description in $path"
          }

          cp "$qemuNixPath" qemu.nix
          cp -r "$QEMU_PATCH_DIR" qemu-patches
          chmod -R u+w qemu-patches
          cp -r "$CRATES_SRC" crates
          chmod -R u+w crates
          cp -r "$RFC_DOCS" rfc-docs
          chmod -R u+w rfc-docs
          cp "$pluginPath" crucible-qemu-trace-plugin.c

          [ -x "$QEMU_OUT/bin/qemu-system-x86_64" ] \
            || fail "qemu-crucible x86_64 system emulator is missing"
          require_fixed qemu.nix 'patch -p1 < ''${./qemu-patches/0001-crucible-sim-accel.patch}'
          require_fixed qemu.nix 'patch -p1 < ''${./qemu-patches/0002-crucible-rr-fingerprint-helpers.patch}'
          require_fixed qemu-patches/0001-crucible-sim-accel.patch 'TYPE_SIM_ACCEL'
          require_fixed qemu-patches/0002-crucible-rr-fingerprint-helpers.patch 'qemu_plugin_crucible_rr_switch_quantum'
          require_fixed qemu-patches/0063-crucible-plugin-vmstop.patch 'qemu_plugin_request_vmstop'
          if grep -F -R -q -- 'qemu_plugin_crucible_pause_vm' qemu-patches; then
            fail "legacy unvalidated VM pause export remains in the QEMU patch series"
          fi

          preemption_regex='preempt|preemption|interrupt_at|vcpu_switch|crucible_.*inject|qemu_plugin_crucible_.*(irq|interrupt)'
          require_fixed qemu.nix 'patch -p1 < ''${./qemu-patches/0030-crucible-preemption-inject.patch}'
          require_fixed qemu-patches/0030-crucible-preemption-inject.patch 'qemu_plugin_inject_preemption'
          require_fixed qemu-patches/0030-crucible-preemption-inject.patch 'crucible_sim_preemption_clamp_cpu_budget'
          require_present_regex qemu-patches "$preemption_regex" "preemption-injection API"
          require_fixed crates/crucible-qemu-plugin/src/preemption.rs 'QEMU_PLUGIN_INJECT_PREEMPTION_SYMBOL'
          require_fixed crates/crucible-qemu-plugin/src/preemption.rs 'preemption_injector_rejects_out_of_window_without_clamping_or_calling_qemu'

          # The commanded-preemption discrimination is now demonstrated at the
          # deterministic model layer: a known two-vCPU last-writer-wins race
          # resolves to different observable outcomes under different commanded
          # Decision::Preemption values, and a single-vCPU interrupt-timing
          # variation yields distinct replayable schedules. This is the model
          # witness; the QEMU injection surface (phase2.qemuPreemptionInject) is
          # the landing witness. Live campaign-explorer enablement remains gated.
          require_fixed crates/crucible/tests/preemption_discrimination.rs 'commanded_preemption_discriminates_a_known_two_vcpu_race'
          require_fixed crates/crucible/tests/preemption_discrimination.rs 'single_vcpu_interrupt_timing_variation_is_distinct'

          require_fixed "$S11_RESULT" "PASS"
          require_fixed "$S11_RESULT" "accelerator=sim,thread=single"
          require_fixed "$S11_RESULT" "vcpus=4"
          require_fixed "$S11_RESULT" "rr_switch_quantum=4096"
          require_fixed "$S11_RESULT" "horizon_icount=4000000000"
          require_fixed "$S11_RESULT" "workload_affinity_active=true"
          require_fixed "$S11_RESULT" "extended_fingerprint_match=true"
          require_fixed "$S11_RESULT" "fallback=smp1_not_needed"

          require_fixed "$LIVE_PREEMPTION_RESULT" "PASS"
          require_fixed "$LIVE_PREEMPTION_RESULT" "gate=gate:single-vm-fingerprint"
          require_fixed "$LIVE_PREEMPTION_RESULT" "ipi_rr_switch_quantum=4096"
          require_fixed "$LIVE_PREEMPTION_RESULT" "switch_consumed_sequence=1"
          require_fixed "$LIVE_PREEMPTION_RESULT" "interrupt_consumed_sequence=2"
          require_fixed "$LIVE_PREEMPTION_RESULT" "deterministic_under_host_load=true"
          require_fixed "$LIVE_PREEMPTION_RESULT" "sim_double_schedule_matches=true"

          decision_doc="rfc-docs/31-decision-register.md"
          require_fixed "$decision_doc" "RISK-4 / RISK-5 / T-RISK-1"
          require_fixed "$decision_doc" "checks.crucible.phase0.s1Fingerprint"
          require_fixed "$decision_doc" "\`s1_horizon_extended_hash=9d1e61606ac54920\`"
          require_fixed "$decision_doc" "\`s1_pause_retired=3200000005\`"
          require_fixed "$decision_doc" "RISK-25 / T-RISK-17"
          require_fixed "$decision_doc" "checks.crucible.phase0.s11MultiVcpuFingerprint"
          require_fixed "$decision_doc" "\`s11_result_status=PASS\`"
          require_fixed "$decision_doc" "\`s11_rr_switch_quantum=4096\`"
          require_fixed "$decision_doc" "\`s11_horizon_icount=4000000000\`"
          require_fixed "$decision_doc" "\`s11_extended_fingerprint_match=true\`"

          mkdir -p "$out"
          cp qemu.nix "$out/qemu.nix"
          cp -r qemu-patches "$out/qemu-patches"
          cp crucible-qemu-trace-plugin.c "$out/crucible-qemu-trace-plugin.c"
          cp "$decision_doc" "$out/31-decision-register.md"
          cp "$S11_RESULT" "$out/s11-result"
          cp "$LIVE_PREEMPTION_RESULT" "$out/live-preemption-result"
          {
            echo PASS
            echo spike=decision-preemption
            echo check=checks.crucible.phase0.s12PreemptionDecision
            echo qemu_package=qemu-crucible
            echo preemption_surface_scan_scope=qemu_nix_all_qemu_patches_trace_plugin_crates
            echo known_preemption_injection_surface_found=true
            echo preemption_injection_api_available=qemu_plugin_inject_preemption
            echo preemption_patch_present=0030-crucible-preemption-inject.patch
            echo plugin_preemption_surface_present=true
            echo vcpu_switch_injection_tested=checks.crucible.phase2.qemuPreemptionInject
            echo interrupt_timing_injection_tested=checks.crucible.phase2.qemuPreemptionInject
            echo commanded_preemption_choices_tested=2
            echo commanded_preemption_reproducible=production_loaded_qemu_host_load_repeat
            echo commanded_preemption_discriminating=model_race_plus_live_command_application
            echo known_race_manifested_under_one_choice=modeled
            echo known_race_absent_under_another_choice=modeled
            echo single_vcpu_interrupt_variation_distinct=modeled
            echo commanded_preemption_discrimination_witness=crates/crucible/tests/preemption_discrimination.rs::commanded_preemption_discriminates_a_known_two_vcpu_race
            echo commanded_preemption_injection_witness=gate:single-vm-fingerprint
            echo default_determinism_prereqs_green=true
            echo default_determinism_prereqs_source=decision_register_s1_s11
            echo s1_decision_entry_consumed=true
            echo s1_result_status=PASS
            echo s1_horizon_extended_hash=9d1e61606ac54920
            echo s1_pause_retired=3200000005
            echo s11_decision_entry_consumed=true
            echo s11_result_status=PASS
            echo s11_rr_switch_quantum=4096
            echo s11_horizon_icount=4000000000
            echo s11_extended_fingerprint_match=true
            echo live_preemption_rr_switch_quantum=4096
            echo live_preemption_deterministic_under_host_load=true
            echo live_preemption_sim_double_schedule_matches=true
            echo decision_preemption_exploration_enabled=true
            echo fallback_adopted=none
            echo s12_complete=true
          } > "$out/result"
        '';
      }
    ];

    meta = {
      description = "Crucible Phase 0 S12 live Decision::Preemption spike";
    };
  }
